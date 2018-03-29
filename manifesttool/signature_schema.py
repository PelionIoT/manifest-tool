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


# This file is a python class representation of the ASN.1 schema defined
# in manifest.asn. It is used to generate a JSON representation of the manifest
# from raw data.
#
# It differs from manifest_definition.py as it's not used by pyasn1, it's not used
# to encode the manifest data nor is it automatically generated.
#
# The process looks like:
#   (Input data) -> (Python object representation) -> (JSON) -> (PyASN1 object) -> ([DER] encoding)
#                             [ this file ]
import time, collections
from manifesttool import utils
from manifesttool.errorhandler import InvalidObject

class BaseObject(object):

    # Basic check to see if all required fields are set.
    # Does NOT check if the set value is of right type accoridng to ASN.1 definition
    def verify(self, required_fields):
        for f in required_fields:
            if self.__dict__.get(f) is None:
                raise InvalidObject("Value for field %r not set, but it's required" % f)

    # Convinience method to just convert object to python dict
    def to_dict(self):
        return utils.todict(self)

class SignedResource(BaseObject):
    def __init__(self, resource, signature):
        self.resource = resource
        self.signature = signature


class CertificateReference(object):
    def __init__(self, fingerprint, uri):
        self.fingerprint = fingerprint
        self.uri = uri

class SignatureBlock(object):
    def __init__(self, signature, certificates):
        self.signature = signature
        self.certificates = certificates

class ResourceSignature(object):
    def __init__(self, hash, signatures):
        self.hash = hash
        self.signatures = signatures
