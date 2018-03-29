# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2017 ARM Limited or its affiliates
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
# This file has been generated using asn1ate (v <unknown>) from './ASN.1/v2/manifest-2.0.0-alpha.asn'
# Last Modified on 2017-07-06 17:12:50
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class ConditionValue(univ.Choice):
    pass


ConditionValue.componentType = namedtype.NamedTypes(
    namedtype.NamedType('int', univ.Integer()),
    namedtype.NamedType('raw', univ.OctetString())
)


class Condition(univ.Sequence):
    pass


Condition.componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', univ.Enumerated(namedValues=namedval.NamedValues(('vendorId', 1), ('classId', 2), ('deviceId', 3), ('lastApplicationTime', 4), ('vendorSpecificMinimum', 2147483648)))),
    namedtype.NamedType('value', ConditionValue())
)


class AlgorithmIdentifier(univ.Sequence):
    pass


AlgorithmIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    namedtype.OptionalNamedType('parameters', univ.Any())
)


class WrappedKey(univ.Sequence):
    pass


WrappedKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('deviceSubjectKeyIdentifier', univ.OctetString()),
    namedtype.NamedType('key', univ.OctetString())
)


class KeyTable(univ.Sequence):
    pass


KeyTable.componentType = namedtype.NamedTypes(
    namedtype.NamedType('keyWrapAlgorithm', AlgorithmIdentifier()),
    namedtype.NamedType('keySize', univ.Integer()),
    namedtype.NamedType('payloadKeyDigest', univ.OctetString()),
    namedtype.NamedType('subjectKeyIdentifier', univ.OctetString()),
    namedtype.NamedType('table', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('uri', char.UTF8String()),
        namedtype.NamedType('integrated', univ.SequenceOf(componentType=WrappedKey()))
    ))
    )
)


class KeyId(univ.OctetString):
    pass


class KdfParameters(univ.Sequence):
    pass


KdfParameters.componentType = namedtype.NamedTypes(
    namedtype.NamedType('kdfAlgorithm', AlgorithmIdentifier()),
    namedtype.NamedType('kdfNonce', univ.OctetString()),
    namedtype.NamedType('keyId', KeyId())
)


class EncryptionInfo(univ.Sequence):
    pass


EncryptionInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('mode', univ.Enumerated(namedValues=namedval.NamedValues(('none', 0), ('preSharedKey', 1), ('preSharedKeyKdf', 2), ('keyTable', 3)))),
    namedtype.NamedType('config', univ.Any()),
    namedtype.NamedType('encryptedPayloadHash', univ.OctetString())
)


class UUID(univ.OctetString):
    pass


class DirectiveRule(univ.Choice):
    pass


DirectiveRule.componentType = namedtype.NamedTypes(
    namedtype.NamedType('int', univ.Integer()),
    namedtype.NamedType('bool', univ.Boolean()),
    namedtype.NamedType('raw', univ.OctetString())
)


class Uri(char.UTF8String):
    pass


class ResourceReference(univ.Sequence):
    pass


ResourceReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType('hash', univ.OctetString()),
    namedtype.NamedType('uri', Uri())
)


class PayloadInfo(univ.Sequence):
    pass


PayloadInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('format', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('enum', univ.Enumerated(namedValues=namedval.NamedValues(('rawBinary', 1), ('hexLocationLengthData', 2), ('elf', 3), ('bsdiff', 4)))),
        namedtype.NamedType('objectId', univ.ObjectIdentifier())
    ))
    ),
    namedtype.OptionalNamedType('encryptionInfo', EncryptionInfo()),
    namedtype.NamedType('storageIdentifier', univ.OctetString()),
    namedtype.NamedType('size', univ.Integer()),
    namedtype.NamedType('payload', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('reference', ResourceReference()),
        namedtype.NamedType('integrated', univ.OctetString())
    ))
    )
)


class TextField(univ.Sequence):
    pass


TextField.componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', univ.Enumerated(namedValues=namedval.NamedValues(('description', 0), ('version', 1), ('vendor', 2), ('model', 3)))),
    namedtype.NamedType('value', char.UTF8String())
)


class AlgorithmIdentifier(univ.Sequence):
    pass


AlgorithmIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    namedtype.OptionalNamedType('parameters', univ.Any())
)


class EncryptionInfo(univ.Sequence):
    pass


EncryptionInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('mode', univ.Enumerated(namedValues=namedval.NamedValues(('none', 0), ('preSharedKey', 1), ('preSharedKeyKdf', 2), ('keyTable', 3)))),
    namedtype.NamedType('config', univ.Any())
)


class Directive(univ.Sequence):
    pass


Directive.componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', univ.Enumerated(namedValues=namedval.NamedValues(('applyImmediately', 1), ('applyAfter', 2), ('restartComponent', 3), ('restartSystem', 4), ('installationHandler', 5), ('vendorSpecificMinimum', 2147483648)))),
    namedtype.NamedType('rule', DirectiveRule())
)


class Manifest(univ.Sequence):
    pass


Manifest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('manifestVersion', univ.Enumerated(namedValues=namedval.NamedValues(('v2', 2)))),
    namedtype.OptionalNamedType('text', univ.SequenceOf(componentType=TextField())),
    namedtype.NamedType('nonce', univ.OctetString()),
    namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
    namedtype.NamedType('timestamp', univ.Integer()),
    namedtype.NamedType('conditions', univ.SequenceOf(componentType=Condition())),
    namedtype.NamedType('directives', univ.SequenceOf(componentType=Directive())),
    namedtype.NamedType('aliases', univ.SequenceOf(componentType=ResourceReference())),
    namedtype.NamedType('dependencies', univ.SequenceOf(componentType=ResourceReference())),
    namedtype.OptionalNamedType('payloadInfo', PayloadInfo())
)


class Payload(univ.OctetString):
    pass


class Bytes(univ.OctetString):
    pass
