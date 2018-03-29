# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Limited or its affiliates
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
#
# This file has been generated using asn1ate (v <unknown>) from './manifesttool/verify/manifest.asn'
# Last Modified on 2017-01-10 11:40:03
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class UUID(univ.OctetString):
    pass


class Manifest(univ.Sequence):
    pass


Manifest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('manifestVersion', univ.Enumerated(namedValues=namedval.NamedValues(('v1', 1)))),
    namedtype.OptionalNamedType('description', char.UTF8String()),
    namedtype.NamedType('timestamp', univ.Integer()),
    namedtype.NamedType('vendorId', UUID()),
    namedtype.NamedType('classId', UUID()),
    namedtype.NamedType('deviceId', UUID()),
    namedtype.NamedType('nonce', univ.OctetString()),
    namedtype.NamedType('vendorInfo', univ.OctetString()),
    namedtype.OptionalNamedType('applyPeriod', univ.Sequence(componentType=namedtype.NamedTypes(
        namedtype.NamedType('validFrom', univ.Integer()),
        namedtype.NamedType('validTo', univ.Integer())
    ))
    ),
    namedtype.NamedType('applyImmediately', univ.Boolean()),
    namedtype.NamedType('encryptionMode', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('enum', univ.Enumerated(namedValues=namedval.NamedValues(('invalid', 0), ('aes-128-ctr-ecc-secp256r1-sha256', 1), ('none-ecc-secp256r1-sha256', 2), ('none-none-sha256', 3), ('none-psk-aes-128-ccm-sha256', 4), ('aes-128-ccm-psk-sha256', 5)))),
        namedtype.NamedType('objectId', univ.ObjectIdentifier())
    ))
    ),
    namedtype.NamedType('aliases', univ.Any()),
    namedtype.NamedType('dependencies', univ.Any()),
    namedtype.OptionalNamedType('payload', univ.Any())
)
