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
"""Package tool module."""
import argparse
import logging
import sys
import enum

from manifesttool.package_tool.actions.create import CreateAction
from manifesttool.package_tool.actions.parse import ParseAction
from manifesttool import __version__

logger = logging.getLogger("manifest-package-tool")


class Actions(enum.Enum):
    """Actions class."""

    CREATE = "create"
    PARSE = "parse"


def get_parser():
    """Get parser."""
    parser = argparse.ArgumentParser(
        description="Tool for creating and verifying combined package files "
        "used for full update campaigns.",
        add_help=False,
    )
    required = parser.add_argument_group("required arguments")

    required.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit."
    )

    actions_parser = parser.add_subparsers(title="Commands", dest="action")
    actions_parser.required = True

    create_parser = actions_parser.add_parser(
        Actions.CREATE.value,
        help="Create a package.",
        description="Create a package.",
        add_help=False,
    )

    CreateAction.register_parser_args(create_parser)

    verify_parser = actions_parser.add_parser(
        Actions.PARSE.value,
        help="Parse and verify a package against the input "
        "validation schema.",
        description="Parse and verify a package against the input "
        "validation schema.",
        add_help=False,
    )
    ParseAction.register_parser_args(verify_parser)
    return parser


def entry_point(argv=sys.argv[1:]):  # pylint: disable=dangerous-default-value
    """Entry point to the package tool."""
    parser = get_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.DEBUG,
    )
    try:
        action = Actions(args.action)
        if action == Actions.PARSE:
            ParseAction.entry_point(args)
        elif action == Actions.CREATE:
            CreateAction.entry_point(args)
        else:
            # will never get here
            raise AssertionError("Invalid action")
    except Exception as ex:  # pylint: disable=broad-except
        logger.error(
            str(ex),
            # exc_info=args.debug
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(entry_point())
