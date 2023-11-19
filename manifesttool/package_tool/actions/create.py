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
"""Package tool create action."""
import argparse
import logging
from pathlib import Path
import jsonschema
import yaml
from manifesttool.common.common_helpers import get_argument_path
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec
from manifesttool.package_tool.package_format.tar_package import (
    PackageFormatTar,
)

PTOOL_PATH = Path(__file__).resolve().parent.parent
logger = logging.getLogger("manifest-package-tool-create")


def _get_alignment_int_argument(value: str) -> int:
    """
    Construct non-negative integer value for an argument.

    :param value: input string
    :return: integer value
    """
    int_value = None
    try:
        int_value = int(value)
    except ValueError:
        pass
    if int_value is None or int_value < 1:
        raise argparse.ArgumentTypeError(
            '"{}" is an invalid alignment value, should be >0'.format(value)
        )
    return int_value


class CreateAction:
    """CreateAction class."""

    @staticmethod
    def register_parser_args(parser: argparse.ArgumentParser):
        """Register parser arguments."""
        required = parser.add_argument_group("required arguments")
        optional = parser.add_argument_group("optional arguments")

        required.add_argument(
            "-c",
            "--config",
            help="Path to the package tool configuration file.",
            metavar="YAML",
            type=get_argument_path,
            required=True,
        )

        required.add_argument(
            "-f",
            "--format",
            help="Package format type.",
            choices=["tar"],  # Add bin when implemented
            default="tar",
        )

        required.add_argument(
            "-a",
            "--image-alignment-size",
            help="Candidate storage read size, \
                used for image alignment. Relevant for embedded devices.",
            default=1,
            type=_get_alignment_int_argument,
        )

        required.add_argument(
            "-o",
            "--output",
            help="Output package filename.",
            type=Path,
            required=True,
        )

        optional.add_argument(
            "-h",
            "--help",
            action="help",
            help="Show this help message and exit.",
        )

    @staticmethod
    def do_create(input_cfg: dict, output_file, format_type):
        """Create method."""
        # validate input against input-schema.json
        schema_path = PTOOL_PATH / "package-schema.json"
        with schema_path.open("rb") as fh:
            input_schema = yaml.safe_load(fh)
            jsonschema.validate(input_cfg, input_schema)

        # create asn1 descriptor
        codec = DescriptorAsnCodec()
        asn1der = codec.encode_package_descriptor(input_cfg)

        if "tar" in format_type:
            package_format = PackageFormatTar()
        else:
            logger.error("Package tool supports only tar format")
            raise NotImplementedError

        package_format.create_package(output_file, input_cfg, asn1der)

    @classmethod
    def entry_point(cls, args: argparse.Namespace) -> None:
        """Entry point to create action."""
        output_file = args.output

        with open(args.config, "rb") as config_fh:
            input_cfg = yaml.safe_load(config_fh)

        cls.do_create(input_cfg, output_file, args.format)
