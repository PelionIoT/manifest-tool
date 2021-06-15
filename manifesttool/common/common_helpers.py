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
from pathlib import Path

def existing_file_path_arg(value):
    """
        Construct Path to an existing file for an argument
        :param value: input string
        :return: constructed Path with semantics
        appropriate for the operating systems
    """
    prospective = Path(value)
    if not prospective.is_file():
        raise argparse.ArgumentTypeError(
            'File "{}" is not found'.format(value)
        )
    return prospective
