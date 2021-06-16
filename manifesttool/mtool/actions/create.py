# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
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

import jsonschema
import yaml

from manifesttool.common.common_helpers import get_argument_path
from manifesttool.common.common_helpers import get_non_negative_int_argument
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.actions import semver_as_tuple_arg_factory
from manifesttool.mtool.asn1 import ManifestAsnCodecBase
from manifesttool.mtool.asn1.v1 import ManifestAsnCodecV1
from manifesttool.mtool import ecdsa_helper

MTOOL_PATH = Path(__file__).resolve().parent.parent

logger = logging.getLogger('manifest-tool-create')


class CreateAction:

    @staticmethod
    def register_parser_args(
            parser: argparse.ArgumentParser, schema_version: str):
        required = parser.add_argument_group('required arguments')
        optional = parser.add_argument_group('optional arguments')

        required.add_argument(
            '-c',
            '--config',
            help='Path to the manifest tool configuration file.',
            metavar='YAML',
            type=argparse.FileType('rb'),
            required=True
        )

        required.add_argument(
            '-k',
            '--key',
            help='Path to the PEM format private key file.',
            metavar='KEY',
            type=argparse.FileType('rb'),
            required=True
        )

        if schema_version == 'v1':
            version_group = optional.add_mutually_exclusive_group()
            version_group.add_argument(
                '-v', '--fw-version',
                type=get_non_negative_int_argument,
                help='Version number (integer) of the candidate image. '
                     'Default: current epoch time.',
                default=int(time.time())
            )
            version_group.add_argument(
                '--fw-migrate-ver',
                type=semver_as_tuple_arg_factory,
                help='Version number of the candidate image in '
                     'SemVer format. NOTE: Use to upgrade from '
                     'v1 manifest schema to a later schema.'
            )

            required.add_argument(
                '--update-certificate',
                type=get_argument_path,
                help='Path to the update certificate file.',
                required=True
            )
        else:
            required.add_argument(
                '-v', '--fw-version',
                type=semantic_version_arg_factory,
                help='Version number of the candidate image in SemVer format. '
                     'Min. 0.0.1, max 999.999.999. '
                     'Must be bigger than the version currently '
                     'in the device(s).',
                required=True
            )

        required.add_argument(
            '-o',
            '--output',
            help='Output manifest filename.',
            type=argparse.FileType('wb'),
            required=True
        )

        optional.add_argument(
            '-h',
            '--help',
            action='help',
            help='Show this help message and exit.'
        )

    @staticmethod
    def do_create(
            pem_key_data: bytes,
            input_cfg: dict,
            fw_version,
            update_certificate: Path,
            asn1_codec_class: Type[ManifestAsnCodecBase]
    ) -> bytes:
        assert fw_version is not None

        codec = asn1_codec_class()

        # validate input against manifest-input-schema.json
        schema_path = MTOOL_PATH / 'manifest-input-schema.json'
        with schema_path.open('rb') as fh:
            input_schema = yaml.safe_load(fh)
            if isinstance(codec, ManifestAsnCodecV1):
                # priority field is optional for v1
                # delete it from required list
                input_schema['required'].remove('priority')
            jsonschema.validate(input_cfg, input_schema)

        raw_signature = True
        if isinstance(codec, ManifestAsnCodecV1):
            raw_signature = False
            cert_data = update_certificate.read_bytes()
            codec.set_update_certificate(cert_data)
        installed_digest = codec.process_input_config(fw_version, input_cfg)

        if input_cfg.get('sign-image'):
            if isinstance(codec, ManifestAsnCodecV1):
                raise AssertionError(
                    'sign-image is unexpected for manifest schema v1')
            signature = ecdsa_helper.ecdsa_sign_prehashed(
                installed_digest, pem_key_data)
            codec.set_image_signature(
                ecdsa_helper.signature_der_to_raw(signature)
            )
        else:
            codec.set_image_signature(bytes())

        der_manifest = codec.get_signed_data()

        signature = ecdsa_helper.ecdsa_sign(der_manifest, pem_key_data)
        if raw_signature:
            signature = ecdsa_helper.signature_der_to_raw(signature)
        manifest_bin = codec.get_der_signed_resource(signature)

        logger.info('Attention: When updating Mbed OS devices,'
                    ' candidate features must match the device\'s'
                    ' bootloader features. Incompatibility may'
                    ' result in damaged devices.')

        return manifest_bin

    @classmethod
    def entry_point(
            cls,
            args: argparse.Namespace,
            asn1_codec: Type[ManifestAsnCodecBase]
    ) -> None:

        input_cfg = yaml.safe_load(args.config)

        if getattr(args, 'fw_migrate_ver', None):
            fw_version = args.fw_migrate_ver[0]
        else:
            fw_version = args.fw_version

        manifest_bin = cls.do_create(
            pem_key_data=args.key.read(),
            input_cfg=input_cfg,
            fw_version=fw_version,
            update_certificate=getattr(args, 'update_certificate', None),
            asn1_codec_class=asn1_codec
        )
        with args.output as fh:
            fh.write(manifest_bin)
