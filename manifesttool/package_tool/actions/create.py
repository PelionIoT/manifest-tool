# ----------------------------------------------------------------------------
# Copyright 2021 Pelion
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
from pathlib import Path
import jsonschema
import yaml
from manifesttool.common.common_helpers import get_argument_path
from manifesttool.common.common_helpers import get_non_negative_int_argument
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec
from manifesttool.package_tool.package_format.tar_package \
    import PackageFormatTar

PTOOL_PATH = Path(__file__).resolve().parent.parent
logger = logging.getLogger('manifest-package-tool-create')

def alignment_size_type(alignment_size):
    alignment_size = int(alignment_size)
    if alignment_size < 1:
        raise argparse.ArgumentTypeError("Minimum alignment size is 1")
    return alignment_size

class CreateAction:

    @staticmethod
    def register_parser_args(
            parser: argparse.ArgumentParser):
        required = parser.add_argument_group('required arguments')
        optional = parser.add_argument_group('optional arguments')

        required.add_argument(
            '-c',
            '--config',
            help='Path to the package tool configuration file.',
            metavar='YAML',
            type=get_argument_path,
            required=True
        )

        required.add_argument(
            '-f',
            '--format',
            help='Package format type.',
            choices=['tar'],  # Add bin when impelemented
            required=True
        )

        required.add_argument(
            '-a',
            '--image-aligment-size',
            help='Candidate storage read size, \
                used for image alignment. Relevant for embedded devices.',
            default=1,
            type=get_non_negative_int_argument
        )

        required.add_argument(
            '-o',
            '--output',
            help='Output package filename.',
            type=Path,
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
        input_cfg: dict,
        output_file,
        format_type
    ):

        # validate input against input-schema.json
        schema_path = PTOOL_PATH / 'package-schema.json'
        with schema_path.open('rb') as fh:
            input_schema = yaml.safe_load(fh)
            jsonschema.validate(input_cfg, input_schema)

        # create asn1 descriptor
        codec = DescriptorAsnCodec()
        asn1der = codec.encode_package_descritpor(input_cfg)

        if 'tar' in format_type:
            package_format = PackageFormatTar()
        else:
            logger.error("Package tool supports only tar format")
            raise NotImplementedError

        package_format.create_package(output_file, input_cfg, asn1der)

    @classmethod
    def entry_point(
            cls,
            args: argparse.Namespace
    ) -> None:

        output_file = args.output

        with open(args.config, "rb") as config_fh:
            input_cfg = yaml.safe_load(config_fh)

        cls.do_create(input_cfg, output_file, args.format)
