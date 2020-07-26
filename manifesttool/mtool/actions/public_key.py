# ----------------------------------------------------------------------------
# Copyright 2019 ARM Limited or its affiliates
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
from pathlib import Path

from manifesttool.mtool import ecdsa_helper
from manifesttool.mtool.actions import existing_file_path_arg_factory


class PublicKeyAction:
    @staticmethod
    def register_parser_args(parser: argparse.ArgumentParser):
        parser.add_argument(
            'key',
            help='Private key PEM file',
            type=existing_file_path_arg_factory
        )

        parser.add_argument(
            '-o', '--out',
            help='Output public key in uncompressed point format (X9.62)',
            type=Path
        )

    @classmethod
    def get_key(cls, private_key_bytes: bytes):
        public_key = ecdsa_helper.public_key_from_private(private_key_bytes)
        public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)
        return public_key_bytes

    @classmethod
    def entry_point(cls, args):
        private_key_bytes = cls.get_key(args.key.read_bytes())
        args.out.write_bytes(private_key_bytes)
