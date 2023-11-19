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
"""Schema action."""
from pathlib import Path

MTOOL_PATH = Path(__file__).resolve().parent.parent


class PrintSchemaAction:
    """PrintSchemaAction class."""

    @staticmethod
    def print_schema():
        """Print schema."""
        schema_file = MTOOL_PATH / "manifest-input-schema.json"
        print(schema_file.read_text())

    @staticmethod
    def register_parser_args(parser):
        """Register parser arguments."""
        optional = parser.add_argument_group("optional arguments")

        optional.add_argument(
            "-h",
            "--help",
            action="help",
            help="Show this help message and exit.",
        )

    @classmethod
    def entry_point(cls, _):
        """Entry point method."""
        cls.print_schema()
