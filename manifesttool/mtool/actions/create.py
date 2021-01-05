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

import jsonschema
import yaml

from manifesttool.mtool.actions import existing_file_path_arg_factory
from manifesttool.mtool.actions import non_negative_int_arg_factory
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.asn1 import ManifestAsnCodecBase
from manifesttool.mtool.asn1.v1 import ManifestAsnCodecV1
from manifesttool.mtool import ecdsa_helper

MTOOL_PATH = Path(__file__).resolve().parent.parent


class CreateAction:

    logger = logging.getLogger('manifest-tool-create')

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
            optional.add_argument(
                '-v', '--fw-version',
                type=non_negative_int_arg_factory,
                help='Version number (integer) of the candidate image. '
                     'Default: current epoch time.',
                default=int(time.time())
            )
            required.add_argument(
                '--update-certificate',
                type=existing_file_path_arg_factory,
                help='Path to the update certificate file.',
                required=True
            )
        else:
            required.add_argument(
                '-v', '--fw-version',
                type=semantic_version_arg_factory,
                help='Version number of the candidate image in SemVer format.',
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
        return codec.get_der_signed_resource(signature)

    @classmethod
    def entry_point(
            cls,
            args: argparse.Namespace,
            asn1_codec: Type[ManifestAsnCodecBase]
    ) -> None:
        input_cfg = yaml.safe_load(args.config)
        schema_path = MTOOL_PATH / 'manifest-input-schema.json'
        with schema_path.open('rb') as fh:
            input_schema = yaml.safe_load(fh)
        jsonschema.validate(input_cfg, input_schema)

        manifest_bin = cls.do_create(
            pem_key_data=args.key.read(),
            input_cfg=input_cfg,
            fw_version=args.fw_version,
            update_certificate=getattr(args, 'update_certificate', None),
            asn1_codec_class=asn1_codec
        )
        with args.output as fh:
            fh.write(manifest_bin)
