# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
#
# This file has been generated using asn1ate (v <unknown>) from './manifesttool/verify/resource.asn'
# Last Modified on 2017-01-10 10:46:42
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class Uri(char.UTF8String):
    pass


class Resource(univ.Sequence):
    pass


Resource.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('uri', Uri()),
    namedtype.NamedType('resourceType', univ.Enumerated(namedValues=namedval.NamedValues(('manifest', 0), ('payload', 1)))),
    namedtype.NamedType('resource', univ.Any())
)
