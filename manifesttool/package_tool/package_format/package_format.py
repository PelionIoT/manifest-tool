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
import abc
import logging
from typing import TypeVar

DESCRIPTOR_FILE_NAME = "_desc_"
CNFG_IMAGES_NAME = "images"
CNFG_FILE_NAME = "file_name"

PackageFormatBaseType = TypeVar(
    'PackageFormatBaseType', bound='PackageFormatBase')

logger = logging.getLogger('package-format')

class PackageFormatBase(abc.ABC):

    @abc.abstractmethod
    def create_package(self, output_file, input_cfg, asn1der):
        raise NotImplementedError

    @staticmethod
    def get_images(input_cfg: dict) -> list:
        images_list = []
        num_of_images = len(input_cfg[CNFG_IMAGES_NAME])

        for img_index in range(0, num_of_images):
            image_dict = (input_cfg[CNFG_IMAGES_NAME])[img_index]
            images_list.append(image_dict[CNFG_FILE_NAME])
        return images_list
