# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
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
