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
"""Actions init."""
import argparse
import re
from pathlib import Path
from typing import List, Tuple


def semantic_version_arg_factory(value) -> str:
    """
    Construct major, minor, split tuple for an argument.

    :param value: input string
    :return: str
    """
    nibble = "([0-9]|[1-9][0-9]{0,2})"
    pattern = "^" + r"\.".join([nibble, nibble, nibble]) + "$"
    if not re.match(pattern, value) or value == "0.0.0":
        raise argparse.ArgumentTypeError(
            '"{}" is not a valid SemVer format. '
            "Min. 0.0.1, max 999.999.999".format(value)
        )
    return value


def _semver_to_int(value: str) -> int:
    """
    Construct integer value for SemVer string.

    :param value: input string in SemVer format
    :return: integer value
    """
    # 'x.y.z' -> 0x008xxx000yyy0zzz
    # Note, result must be same as client
    #  fota_component_version_semver_to_int
    major_bits = 16 + 24
    minor_bits = 16
    split_bits = 0
    major, minor, split = value.split(".")
    return (
        (1 << 55)
        | (int(major) << major_bits)
        | (int(minor) << minor_bits)
        | (int(split) << split_bits)
    )


def semver_as_tuple_arg_factory(value: str) -> Tuple[int, str]:
    """
    Construct major, minor, split tuple for an argument.

    :param value: input string
    :return: tuple of integer value and original str value
    """
    value = semantic_version_arg_factory(value)
    return _semver_to_int(value), value
