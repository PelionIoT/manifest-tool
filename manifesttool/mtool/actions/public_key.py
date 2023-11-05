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
"""Public key method."""
import argparse
from pathlib import Path

from manifesttool.mtool import ecdsa_helper
from manifesttool.common.common_helpers import get_argument_path


class PublicKeyAction:
    """PublicKeyAction class."""

    @staticmethod
    def register_parser_args(parser: argparse.ArgumentParser):
        """Register parser arguments."""
        required = parser.add_argument_group("required arguments")
        optional = parser.add_argument_group("optional arguments")

        required.add_argument(
            "private_key",
            help="Path to a private key PEM file.",
            type=get_argument_path,
        )

        required.add_argument(
            "-o",
            "--out",
            help="Output public key filename.",
            type=Path,
            required=True,
        )

        optional.add_argument(
            "-h",
            "--help",
            action="help",
            help="Show this help message and exit.",
        )

    @classmethod
    def get_key(cls, private_key_bytes: bytes):
        """Get key method."""
        public_key = ecdsa_helper.public_key_from_private(private_key_bytes)
        public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)
        return public_key_bytes

    @classmethod
    def entry_point(cls, args):
        """Entry point method."""
        private_key_bytes = cls.get_key(args.private_key.read_bytes())
        args.out.write_bytes(private_key_bytes)
