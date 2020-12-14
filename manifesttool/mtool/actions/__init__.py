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
import re
from pathlib import Path
from typing import List


def non_negative_int_arg_factory(value: str) -> int:
    """
    Construct non negative integer value for an argument
    :param value: input string
    :return: integer value
    """
    prospective = None
    try:
        prospective = int(value)
    except ValueError:
        pass
    if prospective is None or prospective < 0:
        raise argparse.ArgumentTypeError(
            '"{}" is an invalid non-negative integer value'.format(value))
    return prospective


def semantic_version_arg_factory(value) -> str:
    """
        Construct major, minor, split tuple for an argument
        :param value: input string
        :return: str
    """
    nibble = '([0-9]|[1-9][0-9]{0,2})'
    pattern = r'\.'.join([nibble, nibble, nibble])
    match = re.match(pattern, value)
    if not match:
        raise argparse.ArgumentTypeError(
            '{} is an invalid SemVer. Expecting following pattern {}'.format(
                value, pattern))
    return value


def existing_file_path_arg_factory(value):
    """
        Construct Path to an existing file for an argument
        :param value: input string
        :return: major, minor, split tuple
    """
    prospective = Path(value)
    if not prospective.is_file():
        raise argparse.ArgumentTypeError(
            'File "{}" is not found'.format(value)
        )
    return prospective
