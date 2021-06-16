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
import logging
import tempfile
from pathlib import Path
import os.path
import tarfile
from manifesttool.package_tool.package_format.package_format \
    import PackageFormatBase
from manifesttool.package_tool.package_format.package_format \
    import DESCRIPTOR_FILE_NAME


TAR_TOOL_PATH = Path(__file__).resolve().parent.parent
DESC_FILE = TAR_TOOL_PATH / DESCRIPTOR_FILE_NAME

class PackageFormatTar(PackageFormatBase):
    logger = logging.getLogger('manifest-tar-package')

    def create_package(self, output_file, input_cfg: dict, asn1der):

        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(asn1der)
            desc_path = fh.name

        # Get list of the images
        images_list = self.get_images(input_cfg)

        with tarfile.open(output_file, "w:") as tar_handle:

            # Add descriptor file to the package
            tar_handle.add(desc_path, DESCRIPTOR_FILE_NAME)
            logging.debug('add files')

            # Add all images to the package
            for image in images_list:
                tar_handle.add(image, arcname=os.path.basename(image))
