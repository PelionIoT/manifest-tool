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

class Resource(BaseObject):
    TYPE_MANIFEST, TYPE_FIRMWARE = range(2)

    def __init__(self, resource, resourceType, uri=None):
        self.uri = uri
        self.resourceType = resourceType
        self.resource = resource

        # If type is manifest, then key is manifest. payload if not.
        k = {
            Resource.TYPE_MANIFEST: "manifest",
            Resource.TYPE_FIRMWARE: "payload"
        }[self.resourceType]
        self.resource = {
            k: resource
        }

class Manifest(BaseObject):
    # Manifest version enum values
    V1 = 1

    # Encryption mode enum values
    ENCRYPTION_MODE_INVALID = 0
    ENCRYPTION_MODE_AES_128 = 1
    ENCRYPTION_MODE_NONE_ECC = 2
    ENCRYPTION_MODE_NONE = 3
    ENCRYPTION_MODE_NONE_PSK_CCM_16 = 4
    ENCRYPTION_MODE_PSK_CCM_16 = 4


    def __init__(self, **kwargs):
        # Set defaults
        self.manifestVersion = Manifest.V1
        self.timestamp = int(time.time())
        self.deviceId = None
        self.vendorId = None
        self.classId = None
        self.vendorInfo = None
        self.description = None
        self.nonce = None
        self.applyImmediately = False
        # self.applyPeriod = {
        #     'validFrom': int(time.time()),
        #     'validTo': int(time.time()) + (3600 * 24 * 30)
        # }
        self.applyPeriod = None
        self.encryptionMode = {
            "enum" : Manifest.ENCRYPTION_MODE_NONE
        }
        self.aliases = []
        self.dependencies = []
        self.payload = None

        # Override with kwargs
        for key, value in kwargs.items():
            if value is None:
                continue
            if hasattr(self, key):
                setattr(self, key, value)

        # Check that all required fields are set
        self.verify(["manifestVersion", "timestamp", "deviceId", "vendorId", "classId", "vendorInfo",\
                     "applyImmediately", "dependencies", "nonce", "aliases"])

class PayloadDescription(BaseObject):
    FORMAT_UNDEFINED = 0
    FORMAT_RAW_BINARY = 1
    FORMAT_CBOR = 2
    FORMAT_HEX_LOCATION_LENGTH_DATA = 3
    FORMAT_ELF = 4

    def __init__(self, **kwargs):
        # Set defaults
        self.format = {
            "enum": PayloadDescription.FORMAT_RAW_BINARY
        }
        self.encryptionInfo = None
        self.storageIdentifier = None
        self.reference = None
        self.version = None

        # Override with kwargs
        for key, value in kwargs.items():
            if value is None:
                continue
            if hasattr(self, key):
                setattr(self, key, value)

        # Verify that all required fields are set
        self.verify(["format", "storageIdentifier", "reference"])

class SignedResource(BaseObject):
    def __init__(self, resource, signature):
        self.resource = resource
        self.signature = signature

class ResourceReference(object):
    def __init__(self, hash, size, uri=None):
        self.hash = hash
        self.uri = uri
        self.size = size

class ResourceAlias(object):
    def __init__(self, hash, uri):
        self.hash = hash
        self.uri = uri

class CertificateReference(object):
    def __init__(self, fingerprint, uri):
        self.fingerprint = fingerprint
        self.uri = uri

class SignatureBlock(object):
    def __init__(self, signature, certificates):
        self.signature = signature
        self.certificates = certificates

class MacBlock(object):
    def __init__(self, pskID, keyTableIV, keyTableVersion, keyTableIndexSize, keyTableRecordSize, keyTableRef=None):
        self.pskID = pskID
        self.keyTableIV = keyTableIV
        self.keyTableVersion = keyTableVersion
        self.keyTableRef = keyTableRef
        self.keyTableIndexSize = keyTableIndexSize
        self.keyTableRecordSize = keyTableRecordSize

class ResourceSignature(object):
    def __init__(self, hash, signatures, macs=None):
        self.hash = hash
        self.signatures = signatures
        if macs:
            self.macs = macs
