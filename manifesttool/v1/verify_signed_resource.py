# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-

# This file has been generated using asn1ate (v <unknown>) from './tools/manifest-wrapper.asn'
# Last Modified on 2017-01-06 14:48:42
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class Bytes(univ.OctetString):
    pass


class Uri(char.UTF8String):
    pass


class CertificateReference(univ.Sequence):
    pass


CertificateReference.componentType = namedtype.NamedTypes(
    namedtype.NamedType('fingerprint', Bytes()),
    namedtype.NamedType('uri', Uri())
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
    namedtype.NamedType('resource', univ.Any()),
    namedtype.NamedType('signature', ResourceSignature())
)


class Payload(univ.OctetString):
    pass


class UUID(univ.OctetString):
    pass
