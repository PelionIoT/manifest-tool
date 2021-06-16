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

class ParseAction:

    logger = logging.getLogger('manifest-package-parse')

    @staticmethod
    def register_parser_args(parser):
        required = parser.add_argument_group('required arguments')
        optional = parser.add_argument_group('optional arguments')

        required.add_argument(
            '-p', '--package',
            help='Path to the package file.',
            type=argparse.FileType('rb'),
            required=True
        )

        optional.add_argument(
            '-h',
            '--help',
            action='help',
            help='Show this help message and exit.'
        )

    # pylint: disable=too-many-branches
    @classmethod
    def do_parse(
            cls
    ):

        logging.info(
            '\n----- Package dump start -----\n'
            '%s----- Package dump end -----',

        )

    @classmethod
    def entry_point(cls, args):

        logging.info(args.package)
        cls.do_parse()
