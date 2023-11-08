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
"""Delta tool."""
import argparse
import base64
import hashlib
import logging
import re
import sys
from mmap import mmap, ACCESS_READ
from pathlib import Path

import yaml
from manifesttool.common.common_helpers import get_argument_path
from manifesttool import __version__
from manifesttool import armbsdiff

logger = logging.getLogger("manifest-delta-tool")


def _block_size_factory(value):
    """Check the block size parameter."""
    prospective = None
    try:
        prospective = int(value)
    except ValueError:
        pass
    if not prospective or prospective < 128:
        raise argparse.ArgumentTypeError(
            "{} is invalid - must be at least 128".format(value)
        )
    return prospective


def digest_file(file_path: Path):
    """Perform SHA256 on the file."""
    read_block_size = 65536
    with file_path.open("rb") as fh:
        hash_ctx = hashlib.sha256()
        buf = fh.read(read_block_size)
        while buf:
            hash_ctx.update(buf)
            buf = fh.read(read_block_size)
        file_len = fh.tell()
    return base64.b64encode(hash_ctx.digest()), file_len


def size_check(new_size, delta_size, threshold):
    """
    Assert new fw image is smaller than delta file.

    :param new_size: full new FW image size
    :param delta_size: delta file size
    :param threshold: size difference threshold for aborting the generation.
                      in case evaluates to False - size check will be aborted.
    """
    diff = 100 * float(delta_size) / float(new_size)

    if threshold and diff >= threshold:
        raise AssertionError(
            "Difference with delta image and update image is more than "
            "{} percent! Percentage is: {:.2f}".format(threshold, diff)
        )


def get_version_string_from_bin_file(fname: Path):
    """Get version from the binary file."""
    with fname.open("rb") as fh:
        with mmap(fh.fileno(), 0, access=ACCESS_READ) as my_mmap:
            match = re.search(b"(PELION/BSDIFF\\d{3})", my_mmap)
            if not match:
                raise AssertionError("Version details not found")
            return match.group(0).decode("utf-8")


def check_bsdiff_bspatch_versions(original_image_path: Path):
    """Check if bsdfif and bspatch versions match."""
    bsdiff_version = armbsdiff.get_version()
    logger.info("Current tool version %s", bsdiff_version)
    bspatch_version = get_version_string_from_bin_file(original_image_path)

    if bsdiff_version != bspatch_version:
        logger.error(
            "Bspatch version in {} is incomatible with this version "
            "of delta-tool."
        )

        logger.error(
            "Original image version is: %s",
            bspatch_version.decode("utf-8").split("/")[1],
        )

        logger.error(
            "Current bsdiff version is: %s",
            bsdiff_version.decode("utf-8").split("/")[1],
        )

        raise AssertionError("bsdiff/bspatch version mismatch")


def generate_delta(
    orig_fw: Path, new_fw: Path, output_delta_file: Path, block_size, threshold
):
    """Generate the delta."""
    check_bsdiff_bspatch_versions(orig_fw)

    original_digest, _ = digest_file(orig_fw)
    new_digest, new_size = digest_file(new_fw)

    if original_digest == new_digest:
        logger.warning(
            "New and old file are binary same. This will generate "
            "delta that will not change the original image. "
            "This is probably a mistake"
        )

    try:
        armbsdiff.generate(
            orig_fw.as_posix(),
            new_fw.as_posix(),
            output_delta_file.as_posix(),
            block_size,
        )

        _, delta_size = digest_file(output_delta_file)

        size_check(new_size, delta_size, threshold)
    except AssertionError:
        if output_delta_file.is_file():
            output_delta_file.unlink()
        raise

    delta_cfg_file = output_delta_file.with_suffix(".yaml")
    config = {
        "installed-digest": new_digest,
        "installed-size": new_size,
        "precursor-digest": original_digest,
    }
    with delta_cfg_file.open("wt") as fh:
        yaml.dump(config, fh)


def get_parser():
    """Get argument parser."""
    parser = argparse.ArgumentParser(
        description="Generate delta patch files to be used for "
        "delta update campaigns.",
        add_help=False,
    )
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")

    required.add_argument(
        "-c",
        "--current-fw",
        type=get_argument_path,
        help="Path to the currently installed firmware image, without "
        "headers, for delta update calculation.",
        required=True,
    )
    required.add_argument(
        "-n",
        "--new-fw",
        type=get_argument_path,
        help="Path to the candidate image.",
        required=True,
    )

    required.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output delta patch filename. "
        "NOTE: The delta tool generates an additional "
        "configuration file with the same name but with a '.yaml' "
        "extension. The manifest tool needs both files, "
        "but only this output file must "
        "be uploaded to Pelion storage.",
        required=True,
    )

    optional.add_argument(
        "-b",
        "--block-size",
        type=_block_size_factory,
        help="Compression block size algorithm. "
        "A greater size provides better "
        "compression, but consumes more memory on the device. "
        "Default is 512 bytes. Minimum is 128 bytes. "
        "NOTE: This value MUST be aligned with the "
        "network (COAP/HTTP) buffer size used for download.",
        default=512,
    )

    size_group = optional.add_mutually_exclusive_group()

    # must be first in a group for default value to be set properly
    size_group.add_argument(
        "-t",
        "--threshold",
        type=int,
        choices=range(30, 100),
        metavar="[30-100]",
        default=60,
        help="The ratio of the delta patch size compared to the "
        "candidate image size above which to raise an exception. "
        "Default is 60.",
    )
    size_group.add_argument(
        "--skip-size-check",
        action="store_false",
        dest="threshold",
        help="Skip threshold validations.",
    )

    optional.add_argument(
        "--debug",
        action="store_true",
        help="Print exception info upon exiting.",
    )

    optional.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit."
    )
    optional.add_argument(
        "--version",
        action="version",
        version="Manifest-Tool version {}".format(__version__),
        help="Show program's version number and exit.",
    )

    return parser


def entry_point(argv=sys.argv[1:]):  # pylint: disable=dangerous-default-value
    """Entry point of the delta tool."""
    parser = get_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.DEBUG,
    )

    if args.debug:
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)

    try:
        generate_delta(
            orig_fw=args.current_fw,
            new_fw=args.new_fw,
            output_delta_file=args.output,
            block_size=args.block_size,
            threshold=args.threshold,
        )
    except Exception as ex:  # pylint: disable=broad-except
        logger.error(str(ex), exc_info=args.debug)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(entry_point())
