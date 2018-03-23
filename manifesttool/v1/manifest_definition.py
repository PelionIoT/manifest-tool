# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
#
# This file has been generated using asn1ate (v <unknown>) from './manifest-0.9.6.asn'
# Last Modified on 2016-11-16 10:00:45
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class UUID(univ.OctetString):
    pass


class Uri(char.UTF8String):
    pass


class ResourceReference(univ.Sequence):
    pass


ResourceReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType('hash', univ.OctetString()),
    namedtype.OptionalNamedType('uri', Uri()),
    namedtype.NamedType('size', univ.Integer())
)


class Bytes(univ.OctetString):
    pass


class CertificateReference(univ.Sequence):
    pass


CertificateReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType('fingerprint', Bytes()),
    namedtype.NamedType('uri', Uri())
)


class PayloadDescription(univ.Sequence):
    pass


PayloadDescription.componentType = namedtype.NamedTypes(
    namedtype.NamedType('format', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('enum', univ.Enumerated(namedValues=namedval.NamedValues(('undefined', 0), ('raw-binary', 1), ('cbor', 2), ('hex-location-length-data', 3), ('elf', 4)))),
        namedtype.NamedType('objectId', univ.ObjectIdentifier())
    ))
    ),
    namedtype.OptionalNamedType('encryptionInfo', univ.Sequence(componentType=namedtype.NamedTypes(
        namedtype.NamedType('initVector', univ.OctetString()),
        namedtype.NamedType('id', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('key', univ.OctetString()),
            namedtype.NamedType('certificate', CertificateReference())
        ))
        ),
        namedtype.OptionalNamedType('key', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('keyTable', Uri()),
            namedtype.NamedType('cipherKey', univ.OctetString())
        ))
        )
    ))
    ),
    namedtype.NamedType('storageIdentifier', char.UTF8String()),
    namedtype.NamedType('reference', ResourceReference()),
    namedtype.OptionalNamedType('version', char.UTF8String())
)


class ResourceAlias(univ.Sequence):
    pass


ResourceAlias.componentType = namedtype.NamedTypes(
    namedtype.NamedType('hash', univ.OctetString()),
    namedtype.NamedType('uri', Uri())
)


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
        namedtype.NamedType('enum', univ.Enumerated(namedValues=namedval.NamedValues(('invalid', 0), ('aes-128-ctr-ecc-secp256r1-sha256', 1), ('none-ecc-secp256r1-sha256', 2), ('none-none-sha256', 3)))),
        namedtype.NamedType('objectId', univ.ObjectIdentifier())
    ))
    ),
    namedtype.NamedType('aliases', univ.SequenceOf(componentType=ResourceAlias())),
    namedtype.NamedType('dependencies', univ.SequenceOf(componentType=ResourceReference())),
    namedtype.OptionalNamedType('payload', PayloadDescription())
)


class Payload(univ.OctetString):
    pass


class Resource(univ.Sequence):
    pass


Resource.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('uri', Uri()),
    namedtype.NamedType('resourceType', univ.Enumerated(namedValues=namedval.NamedValues(('manifest', 0), ('payload', 1)))),
    namedtype.NamedType('resource', univ.Choice(componentType=namedtype.NamedTypes(
        namedtype.NamedType('manifest', Manifest()),
        namedtype.NamedType('payload', Payload())
    ))
    )
)


class SignatureBlock(univ.Sequence):
    pass


SignatureBlock.componentType = namedtype.NamedTypes(
    namedtype.NamedType('signature', univ.OctetString()),
    namedtype.NamedType('certificates', univ.SequenceOf(componentType=CertificateReference()))
)


class ResourceSignature(univ.Sequence):
    pass


ResourceSignature.componentType = namedtype.NamedTypes(
    namedtype.NamedType('hash', univ.OctetString()),
    namedtype.NamedType('signatures', univ.SequenceOf(componentType=SignatureBlock()))
)


class SignedResource(univ.Sequence):
    pass


SignedResource.componentType = namedtype.NamedTypes(
    namedtype.NamedType('resource', Resource()),
    namedtype.NamedType('signature', ResourceSignature())
)
