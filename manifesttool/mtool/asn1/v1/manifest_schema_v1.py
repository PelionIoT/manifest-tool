# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
# Auto-generated by asn1ate v.0.6.0 from manifest-1.0.0
# (last modified on 2020-01-26 09:34:14.860967)
"""Manifest tool V1 schema."""
from pyasn1.type import (
    univ,
    char,
    namedtype,
    namedval,
    tag,
    constraint,
    useful,
)


class Bytes(univ.OctetString):
    """Bytes class."""

    pass


class Uri(char.UTF8String):
    """URI class."""

    pass


class CertificateReference(univ.Sequence):
    """CertificateReference class."""

    pass


CertificateReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType("fingerprint", Bytes()),
    namedtype.NamedType("uri", Uri()),
)


class KeyTableEntry(univ.Sequence):
    """KeyTableEntry class."""

    pass


KeyTableEntry.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType(
        "hash",
        univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ),
    ),
    namedtype.OptionalNamedType(
        "payloadKey",
        univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ),
    ),
)


class MacBlock(univ.Sequence):
    """MacBlock class."""

    pass


MacBlock.componentType = namedtype.NamedTypes(
    namedtype.NamedType("pskID", univ.OctetString()),
    namedtype.NamedType("keyTableVersion", univ.Integer()),
    namedtype.OptionalNamedType("keyTableIV", univ.OctetString()),
    namedtype.OptionalNamedType("keyTableRef", char.UTF8String()),
    namedtype.NamedType("keyTableIndexSize", univ.Integer()),
    namedtype.NamedType("keyTableRecordSize", univ.Integer()),
)


class ResourceReference(univ.Sequence):
    """ResourceReference class."""

    pass


ResourceReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType("hash", univ.OctetString()),
    namedtype.OptionalNamedType("uri", Uri()),
    namedtype.NamedType("size", univ.Integer()),
)


class PayloadDescription(univ.Sequence):
    """PayloadDescription class."""

    pass


PayloadDescription.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "format",
        univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType(
                    "enum",
                    univ.Enumerated(
                        namedValues=namedval.NamedValues(
                            ("undefined", 0),
                            ("raw-binary", 1),
                            ("cbor", 2),
                            ("hex-location-length-data", 3),
                            ("elf", 4),
                            ("bsdiff-stream", 5),
                        )
                    ),
                ),
                namedtype.NamedType("objectId", univ.ObjectIdentifier()),
            )
        ),
    ),
    namedtype.OptionalNamedType(
        "encryptionInfo",
        univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("initVector", univ.OctetString()),
                namedtype.NamedType(
                    "id",
                    univ.Choice(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType("key", univ.OctetString()),
                            namedtype.NamedType(
                                "certificate", CertificateReference()
                            ),
                        )
                    ),
                ),
                namedtype.OptionalNamedType(
                    "key",
                    univ.Choice(
                        componentType=namedtype.NamedTypes(
                            namedtype.NamedType("keyTable", Uri()),
                            namedtype.NamedType(
                                "cipherKey", univ.OctetString()
                            ),
                        )
                    ),
                ),
            )
        ),
    ),
    namedtype.NamedType("storageIdentifier", char.UTF8String()),
    namedtype.NamedType("reference", ResourceReference()),
    namedtype.OptionalNamedType("installedSize", univ.Integer()),
    namedtype.OptionalNamedType("installedDigest", univ.OctetString()),
    namedtype.OptionalNamedType("version", char.UTF8String()),
)


class ResourceAlias(univ.Sequence):
    """ResourceAlias class."""

    pass


ResourceAlias.componentType = namedtype.NamedTypes(
    namedtype.NamedType("hash", univ.OctetString()),
    namedtype.NamedType("uri", Uri()),
)


class UUID(univ.OctetString):
    """UUID class."""

    pass


class Manifest(univ.Sequence):
    """Manifest class."""

    pass


Manifest.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "manifestVersion",
        univ.Enumerated(namedValues=namedval.NamedValues(("v1", 1))),
    ),
    namedtype.OptionalNamedType("description", char.UTF8String()),
    namedtype.NamedType("timestamp", univ.Integer()),
    namedtype.NamedType("vendorId", UUID()),
    namedtype.NamedType("classId", UUID()),
    namedtype.NamedType("deviceId", UUID()),
    namedtype.NamedType("nonce", univ.OctetString()),
    namedtype.NamedType("vendorInfo", univ.OctetString()),
    namedtype.OptionalNamedType("precursorDigest", univ.OctetString()),
    namedtype.OptionalNamedType(
        "applyPeriod",
        univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("validFrom", univ.Integer()),
                namedtype.NamedType("validTo", univ.Integer()),
            )
        ),
    ),
    namedtype.NamedType("applyImmediately", univ.Boolean()),
    namedtype.OptionalNamedType("priority", univ.Integer()),
    namedtype.NamedType(
        "encryptionMode",
        univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType(
                    "enum",
                    univ.Enumerated(
                        namedValues=namedval.NamedValues(
                            ("invalid", 0),
                            ("aes-128-ctr-ecc-secp256r1-sha256", 1),
                            ("none-ecc-secp256r1-sha256", 2),
                            ("none-none-sha256", 3),
                            ("none-psk-aes-128-ccm-sha256", 4),
                            ("aes-128-ccm-psk-sha256", 5),
                        )
                    ),
                ),
                namedtype.NamedType("objectId", univ.ObjectIdentifier()),
            )
        ),
    ),
    namedtype.NamedType(
        "aliases", univ.SequenceOf(componentType=ResourceAlias())
    ),
    namedtype.NamedType(
        "dependencies", univ.SequenceOf(componentType=ResourceReference())
    ),
    namedtype.OptionalNamedType("payload", PayloadDescription()),
)


class Payload(univ.OctetString):
    """Payload class."""

    pass


class Resource(univ.Sequence):
    """Resource class."""

    pass


Resource.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType("uri", Uri()),
    namedtype.NamedType(
        "resourceType",
        univ.Enumerated(
            namedValues=namedval.NamedValues(("manifest", 0), ("payload", 1))
        ),
    ),
    namedtype.NamedType(
        "resource",
        univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("manifest", Manifest()),
                namedtype.NamedType("payload", Payload()),
            )
        ),
    ),
)


class SignatureBlock(univ.Sequence):
    """SignatureBlock class."""

    pass


SignatureBlock.componentType = namedtype.NamedTypes(
    namedtype.NamedType("signature", univ.OctetString()),
    namedtype.NamedType(
        "certificates", univ.SequenceOf(componentType=CertificateReference())
    ),
)


class ResourceSignature(univ.Sequence):
    """ResourceSignature class."""

    pass


ResourceSignature.componentType = namedtype.NamedTypes(
    namedtype.NamedType("hash", univ.OctetString()),
    namedtype.NamedType(
        "signatures", univ.SequenceOf(componentType=SignatureBlock())
    ),
    namedtype.OptionalNamedType(
        "macs", univ.SequenceOf(componentType=MacBlock())
    ),
)


class SignedResource(univ.Sequence):
    """SignedResource class."""

    pass


SignedResource.componentType = namedtype.NamedTypes(
    namedtype.NamedType("resource", Resource()),
    namedtype.NamedType("signature", ResourceSignature()),
)
