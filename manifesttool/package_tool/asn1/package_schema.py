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
# Auto-generated by asn1ate v.0.6.0 from package.asn
# (last modified on 2021-06-20 18:27:49.888380)

from pyasn1.type import univ, char, namedtype, constraint


class String(char.UTF8String):
    pass


class ImgDescriptor(univ.Sequence):
    pass


ImgDescriptor.componentType = namedtype.NamedTypes(
    namedtype.NamedType('id', String()),
    namedtype.NamedType('vendor-data', String()),
    namedtype.NamedType('image-size', univ.Integer())
)


class Descriptor(univ.Sequence):
    pass


Descriptor.componentType = namedtype.NamedTypes(
    namedtype.NamedType('num-of-images', \
        univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, 255))),
    namedtype.NamedType('descriptors-array', univ.SequenceOf(componentType=ImgDescriptor()))
)


class Int(univ.Integer):
    pass
