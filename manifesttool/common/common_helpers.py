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
"""Helper functions."""
import argparse
from pathlib import Path


def get_argument_path(value):
    """
    Construct Path to an existing file for an argument.

    :param value: input string
    :return: constructed Path with semantics
    appropriate for the operating systems
    """
    arg_path = Path(value)
    if not arg_path.is_file():
        raise argparse.ArgumentTypeError(
            'File "{}" is not found'.format(value)
        )
    return arg_path


def get_file_size(path_file: Path):
    """Get file size."""
    return Path(path_file).stat().st_size


def get_non_negative_int_argument(value: str) -> int:
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
    if int_value is None or int_value < 0:
        raise argparse.ArgumentTypeError(
            '"{}" is an invalid non-negative integer value'.format(value)
        )
    return int_value
