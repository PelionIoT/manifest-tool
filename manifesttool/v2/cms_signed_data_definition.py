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
# This file has been generated using asn1ate (v <unknown>) from './ASN.1/v1/cms-sig-minimal.asn'
# Last Modified on 2017-06-20 14:10:47
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class AttributeValue(univ.Any):
    pass


class Attribute(univ.Sequence):
    pass


Attribute.componentType = namedtype.NamedTypes(
    namedtype.NamedType('attrType', univ.ObjectIdentifier()),
    namedtype.NamedType('attrValues', univ.SetOf(componentType=AttributeValue()))
)


class SignedAttributes(univ.SetOf):
    pass


SignedAttributes.componentType = Attribute()
SignedAttributes.subtypeSpec=constraint.ValueSizeConstraint(1, 4)


class SignatureValue(univ.OctetString):
    pass


class AlgorithmIdentifier(univ.Sequence):
    pass


AlgorithmIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    namedtype.OptionalNamedType('parameters', univ.Any())
)


class SubjectKeyIdentifier(univ.OctetString):
    pass


class SignerIdentifier(univ.Choice):
    pass


SignerIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType('subjectKeyIdentifier', SubjectKeyIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
)


class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class DigestAlgorithmIdentifiers(univ.SetOf):
    pass


DigestAlgorithmIdentifiers.componentType = DigestAlgorithmIdentifier()


class ContentType(univ.ObjectIdentifier):
    pass


class EncapsulatedContentInfo(univ.Sequence):
    pass


EncapsulatedContentInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('eContentType', ContentType()),
    namedtype.NamedType('eContent', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
)


class SignatureAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class CMSVersion(univ.Integer):
    pass


CMSVersion.namedValues = namedval.NamedValues(
    ('v0', 0),
    ('v1', 1),
    ('v2', 2),
    ('v3', 3),
    ('v4', 4),
    ('v5', 5)
)


class SignerInfo(univ.Sequence):
    pass


SignerInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', CMSVersion()),
    namedtype.NamedType('sid', SignerIdentifier()),
    namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
    namedtype.OptionalNamedType('signedAttrs', SignedAttributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
    namedtype.NamedType('signature', SignatureValue())
)


class SignerInfos(univ.SetOf):
    pass


SignerInfos.componentType = SignerInfo()


class SignedData(univ.Sequence):
    pass


SignedData.componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', CMSVersion()),
    namedtype.NamedType('digestAlgorithms', DigestAlgorithmIdentifiers()),
    namedtype.NamedType('encapContentInfo', EncapsulatedContentInfo()),
    namedtype.NamedType('signerInfos', SignerInfos())
)


class ContentChoices(univ.Choice):
    pass


ContentChoices.componentType = namedtype.NamedTypes(
    namedtype.NamedType('signedData', SignedData())
)


class ContentInfo(univ.Sequence):
    pass


ContentInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('contentType', ContentType()),
    namedtype.NamedType('content', ContentChoices().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
)
