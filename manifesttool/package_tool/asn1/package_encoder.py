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
"""ASN1 package encoder."""
import logging
from collections import OrderedDict
from pyasn1.codec.native.encoder import encode as native_encoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type.univ import SequenceOf
from manifesttool.package_tool.asn1 import package_schema
from manifesttool.common.common_helpers import get_file_size


class DescriptorAsnCodec:
    """DescriptorAsnCodec class."""

    logger = logging.getLogger("descriptor-codec")

    def __init__(self, dom=None):
        """Init the class."""
        if dom:
            self.dom = dom
        else:
            self.dom = package_schema.Descriptor()
            self.dom["descriptors-array"] = SequenceOf()

    def set_asn1_descriptor(self, input_cfg: dict):
        """Set ASN1 descriptor."""
        self.dom["num-of-images"] = len(input_cfg["images"])

        for image in input_cfg["images"]:
            img_descriptor = self.get_img_descriptor(image)
            self.dom["descriptors-array"].append(img_descriptor)

    @staticmethod
    def get_img_descriptor(image):
        """Get image descriptor."""
        image_descriptor = package_schema.ImgDescriptor()
        image_descriptor["id"] = image["sub_comp_name"]
        image_descriptor["vendor-data"] = image["vendor_data"]
        image_descriptor["vendor-data-size"] = len(image["vendor_data"])
        image_descriptor["image-size"] = get_file_size(image["file_name"])

        return image_descriptor

    def encode_package_descriptor(self, input_cfg: dict) -> bytes:
        """Encode package descriptor."""
        self.set_asn1_descriptor(input_cfg)
        return der_encoder.encode(self.dom)

    @classmethod
    def decode(cls, data: bytes) -> OrderedDict:
        """Decode the package."""
        package_dom = der_decoder.decode(
            data, asn1Spec=package_schema.Descriptor()
        )[0]

        return native_encoder(package_dom)
