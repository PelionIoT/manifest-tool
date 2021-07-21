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

PackageFormatBaseType = TypeVar(
    'PackageFormatBaseType', bound='PackageFormatBase')

logger = logging.getLogger('package-format')

class PackageFormatBase(abc.ABC):

    @abc.abstractmethod
    def parse_package(self, package_file):
        raise NotImplementedError

    @abc.abstractmethod
    def create_package(self, output_file, input_cfg, asn1der):
        raise NotImplementedError
