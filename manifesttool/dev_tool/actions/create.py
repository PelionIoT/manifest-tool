# ----------------------------------------------------------------------------
# Copyright 2019-2020 Pelion
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import yaml

from manifesttool.dev_tool import defaults
from manifesttool.mtool.actions import existing_file_path_arg_factory
from manifesttool.mtool.actions import non_negative_int_arg_factory
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.actions.create import CreateAction
from manifesttool.mtool.asn1 import ManifestAsnCodecBase
from manifesttool.mtool.payload_format import PayloadFormat

logger = logging.getLogger('manifest-dev-tool-create')


def register_parser(parser: argparse.ArgumentParser,
                    schema_version: str,
                    is_update_parser: bool = False):

    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    if not is_update_parser:
        required.add_argument(
            '-u', '--payload-url',
            help='Address from which the device downloads '
                 'the candidate payload.',
            required=True
        )

    required.add_argument(
        '-p', '--payload-path',
        help='Local path to the candidate payload file.',
        type=existing_file_path_arg_factory,
        required=True
    )

    if not is_update_parser:
        required.add_argument(
            '-o', '--output',
            help='Output manifest filename.',
            type=argparse.FileType('wb'),
            required=True
        )

    if schema_version == 'v1':
        optional.add_argument(
            '-v', '--fw-version',
            type=non_negative_int_arg_factory,
            help='Version number (integer) of the candidate image. '
                 'Default: current epoch time.',
            default=int(time.time())
        )
        optional.add_argument(
            '-r', '--priority',
            type=int,
            help='Set update priority.'
        )
    else:
        optional.add_argument(
            '-v', '--fw-version',
            type=semantic_version_arg_factory,
            help='Version number of the candidate image in SemVer format.'
        )
        optional.add_argument(
            '--component-name',
            default='MAIN',
            metavar='NAME',
            help='The name of the component to be udpated. '
                 'Must correspond to an existing component '
                 'name on target devices.'
        )
        if is_update_parser:
            optional.add_argument(
                '-u', '--use-short-url',
                action='store_true',
                help='Use a short candidate payload URL in the manifest. '
                     'Note: the device must be configured to use CoAP.'
            )
        optional.add_argument(
            '-m', '--sign-image',
            action='store_true',
            help='Sign image. Use only when the bootloader on a device '
                 'expects a signed FW image.'
        )
        optional.add_argument(
            '-r', '--priority',
            type=non_negative_int_arg_factory,
            help='Set update priority >=0. [Default: 0]',
            default=0
        )

    optional.add_argument(
        '-d', '--vendor-data',
        help='Path to a vendor custom data file - to be passed to '
             'the target devices.',
        type=existing_file_path_arg_factory
    )

    optional.add_argument(
        '--cache-dir',
        help='Tool\'s cache directory. '
             'Must match the directory used by the "init" command.',
        type=Path,
        default=defaults.BASE_PATH
    )

    optional.add_argument(
        '-h',
        '--help',
        action='help',
        help='Show this help message and exit.'
    )


def create_dev_manifest(
        dev_cfg: dict,
        manifest_version: Type[ManifestAsnCodecBase],
        vendor_data_path: Path,
        payload_path: Path,
        payload_url: str,
        priority: int,
        fw_version: str,
        sign_image: bool,
        component: str
):

    key_file = Path(dev_cfg['key_file'])
    if not key_file.is_file():
        raise AssertionError('{} not found'.format(key_file.as_posix()))
    key_data = key_file.read_bytes()

    payload_file = payload_path
    delta_meta_file = payload_file.with_suffix('.yaml')

    if delta_meta_file.is_file():
        payload_format = PayloadFormat.PATCH
    else:
        payload_format = PayloadFormat.RAW

    input_cfg = {
        'vendor': {
            'vendor-id': dev_cfg['vendor-id']
        },
        'device': {
            'class-id': dev_cfg['class-id']
        },
        'payload': {
            'url': payload_url,
            'file-path': payload_path.as_posix(),
            'format': payload_format.value
        }
    }

    if priority is not None:
        input_cfg['priority'] = priority

    if manifest_version.get_name() != 'v1':
        input_cfg['sign-image'] = sign_image
        input_cfg['component'] = component

    if vendor_data_path:
        input_cfg['vendor']['custom-data-path'] = vendor_data_path.as_posix()

    manifest_bin = CreateAction.do_create(
        pem_key_data=key_data,
        input_cfg=input_cfg,
        fw_version=fw_version,
        update_certificate=Path(dev_cfg['certificate']),
        asn1_codec_class=manifest_version
    )
    logger.info(
        'Created manifest in %s schema for %s update campaign',
        manifest_version.get_name(),
        'delta' if payload_format == PayloadFormat.PATCH else 'full'
    )
    return manifest_bin

def bump_minor(sem_ver: str):
    major, minor, split = sem_ver.split('.')
    split = str(int(split) + 1)
    return '{}.{}.{}'.format(major, minor, split)

def entry_point(
        args,
        manifest_version: Type[ManifestAsnCodecBase]
):
    cache_dir = args.cache_dir

    if not cache_dir.is_dir():
        raise AssertionError(
            'Tool cache directory is missing. '
            'Execute "init" command to create it.')

    with (cache_dir / defaults.DEV_CFG).open('rt') as fh:
        dev_cfg = yaml.safe_load(fh)

    component_name = getattr(args, 'component_name', None)
    cache_fw_version_file = cache_dir / defaults.UPDATE_VERSION
    fw_version = args.fw_version
    if 'v1' not in manifest_version.get_name():
        if cache_fw_version_file.is_file():
            with cache_fw_version_file.open('rt') as fh:
                cached_versions = yaml.safe_load(fh)
        else:
            cached_versions = dict()
        if not fw_version:
            fw_version = cached_versions.get(component_name, '0.0.1')
            fw_version = bump_minor(fw_version)

        cached_versions[component_name] = fw_version

        with cache_fw_version_file.open('wt') as fh:
            yaml.dump(cached_versions, fh)
        logger.info('FW version: %s', fw_version)
    else:
        assert fw_version is not None
        logger.info('FW version: %d', fw_version)

    manifest_bin = create_dev_manifest(
        dev_cfg=dev_cfg,
        manifest_version=manifest_version,
        vendor_data_path=args.vendor_data,
        payload_path=args.payload_path,
        payload_url=args.payload_url,
        priority=args.priority,
        fw_version=fw_version,
        sign_image=getattr(args, 'sign_image', False),
        component=getattr(args, 'component_name', None)
    )

    with args.output as fh:
        fh.write(manifest_bin)
