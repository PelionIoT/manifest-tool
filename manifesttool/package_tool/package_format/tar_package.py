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
"""Tar package logic."""
import logging
import tempfile
from pathlib import Path
import tarfile
from manifesttool.package_tool.package_format.package_format import (
    PackageFormatBase,
)
from manifesttool.package_tool.package_format.package_format import (
    DESCRIPTOR_FILE_NAME,
)
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec

TAR_TOOL_PATH = Path(__file__).resolve().parent.parent
DESC_FILE = TAR_TOOL_PATH / DESCRIPTOR_FILE_NAME


class PackageFormatTar(PackageFormatBase):
    """PackageFormatTar class."""

    logger = logging.getLogger("manifest-tar-package")

    def create_package(self, output_file, input_cfg: dict, asn1der):
        """Create tar package."""
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(asn1der)
            fh.close()

            with tarfile.open(output_file, "w:") as tar_handle:

                # Add descriptor file to the package
                tar_handle.add(fh.name, DESCRIPTOR_FILE_NAME)
                Path(fh.name).unlink()

                logging.debug("add files")
                # Add all images to the package
                for image in input_cfg["images"]:
                    tar_handle.add(image["file_name"], image["sub_comp_name"])

    def parse_package(self, package_file):
        """Parse tar package."""
        with tarfile.open(package_file, "r:") as tar_arch:
            logging.info("Contents of the tar package - ")
            for tarinfo in tar_arch:
                logging.info("File name : %s", tarinfo.name)
                if tarinfo.name in DESCRIPTOR_FILE_NAME:
                    with tar_arch.extractfile(DESCRIPTOR_FILE_NAME) as desc_fh:
                        asn1der = desc_fh.read()
                    asn1_dict = DescriptorAsnCodec.decode(asn1der)

        logging.info("Information of update images:")
        for img in asn1_dict["descriptors-array"]:
            logging.info(img)
