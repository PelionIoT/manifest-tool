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
