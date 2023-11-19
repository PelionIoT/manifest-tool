# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
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
"""Manifest tool V1 encoder."""
import hashlib
import logging
import time
from collections import OrderedDict
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native.encoder import encode as native_encoder
from pyasn1.type.univ import SequenceOf

from manifesttool.mtool import ecdsa_helper
from manifesttool.mtool.asn1.manifest_codec import ManifestAsnCodecBase
from manifesttool.mtool.asn1.v1 import manifest_schema_v1 as schema


class ManifestAsnCodecV1(ManifestAsnCodecBase):
    """ManifestAsnCodecV1 class."""

    VERSION = "v1"

    logger = logging.getLogger("v1-manifest-codec")

    def __init__(self, dom=None):
        """Init method."""
        # Call the __init__ method of the base class.
        super().__init__()
        if dom:
            self.dom = dom
        else:
            self.dom = schema.Resource()
            self.dom["resourceType"] = "manifest"
            self.dom["resource"]["manifest"] = schema.Manifest()
            self.dom["resource"]["manifest"]["manifestVersion"] = "v1"
            self.dom["resource"]["manifest"]["nonce"] = b""
            self.dom["resource"]["manifest"]["deviceId"] = b""
            self.dom["resource"]["manifest"]["vendorInfo"] = b""
            self.dom["resource"]["manifest"]["applyImmediately"] = True
            self.dom["resource"]["manifest"]["encryptionMode"][
                "enum"
            ] = "none-ecc-secp256r1-sha256"
            self.dom["resource"]["manifest"][
                "payload"
            ] = schema.PayloadDescription()
            self.dom["resource"]["manifest"]["payload"][
                "storageIdentifier"
            ] = "default"
            self.dom["resource"]["manifest"]["payload"][
                "reference"
            ] = schema.ResourceReference()
            self.fingerprint = None

    @classmethod
    def get_name(cls) -> str:
        """Get name."""
        return cls.VERSION

    def get_der_signed_resource(self, signature: bytes) -> bytes:
        """Get DER signed resource."""
        hash_ctx = hashlib.sha256()
        hash_ctx.update(self.get_signed_data())
        signed_digest = hash_ctx.digest()

        resource_signature_dom = schema.ResourceSignature()
        resource_signature_dom["hash"] = signed_digest
        signature_block = schema.SignatureBlock()
        signature_block["signature"] = signature
        signature_block["certificates"] = SequenceOf()
        certificate_reference = schema.CertificateReference()
        certificate_reference["fingerprint"] = self.fingerprint
        certificate_reference["uri"] = ""
        signature_block["certificates"].append(certificate_reference)
        resource_signature_dom["signatures"] = SequenceOf()
        resource_signature_dom["signatures"].append(signature_block)

        signed_resource_dom = schema.SignedResource()
        signed_resource_dom["resource"] = self.dom
        signed_resource_dom["signature"] = resource_signature_dom

        return der_encoder.encode(signed_resource_dom)

    def get_signed_data(self) -> bytes:
        """Get signed data."""
        return der_encoder.encode(self.dom)

    @classmethod
    def decode(
        cls, data: bytes, verification_key: Optional[ec.EllipticCurvePublicKey]
    ) -> OrderedDict:
        """Decode."""
        signed_resource_dom = der_decoder.decode(
            data, asn1Spec=schema.SignedResource()
        )[0]
        if not verification_key:
            return native_encoder(signed_resource_dom)

        codec = ManifestAsnCodecV1(dom=signed_resource_dom["resource"])
        signed_data = codec.get_signed_data()
        signature = bytes(
            signed_resource_dom["signature"]["signatures"][0]["signature"]
        )

        try:
            ecdsa_helper.ecdsa_verify(
                public_key=verification_key,
                signed_data=signed_data,
                signature=signature,
            )
            cls.logger.info("Manifest Signature verified!")
        except InvalidSignature as ex:
            raise AssertionError(
                "Manifest Signature verification failed"
            ) from ex
        return native_encoder(signed_resource_dom)

    def set_payload_version(self, version: str):
        """Set payload version."""
        if version:
            try:
                version_number = int(version)
            except ValueError as ex:
                raise AssertionError(
                    "invalid version {} - version must be "
                    "a valid positive integer".format(version)
                ) from ex
        else:
            version_number = int(time.time())
        self.dom["resource"]["manifest"]["timestamp"] = version_number

    def set_update_priority(self, priority: int):
        """Set priority."""
        self.dom["resource"]["manifest"]["priority"] = priority

    def set_vendor_id(self, vendor_id: bytes):
        """Set vendor id."""
        self.dom["resource"]["manifest"]["vendorId"] = vendor_id

    def set_vendor_data(self, data: bytes):
        """Set vendor data."""
        self.dom["resource"]["manifest"]["vendorInfo"] = data

    def set_class_id(self, class_id: bytes):
        """Set class id."""
        self.dom["resource"]["manifest"]["classId"] = class_id

    def set_device_id(self, device_id: bytes):
        """Set device id."""
        self.dom["resource"]["manifest"]["classId"] = device_id

    def set_payload_fingerprint(self, digest: bytes, size: int):
        """Set payload fingerprint."""
        self.dom["resource"]["manifest"]["payload"]["reference"][
            "hash"
        ] = digest
        self.dom["resource"]["manifest"]["payload"]["reference"]["size"] = size

    def set_payload_uri(self, uri: str):
        """Set payload URI."""
        self.dom["resource"]["manifest"]["payload"]["reference"]["uri"] = uri

    def set_payload_format(self, payload_format: str):
        """Set payload format."""
        _format = payload_format
        if payload_format == "arm-patch-stream":
            _format = "bsdiff-stream"
        self.dom["resource"]["manifest"]["payload"]["format"]["enum"] = _format

    def set_payload_metadata(
        self,
        installed_digest: bytes,
        installed_size: int,
        precursor_digest: bytes,
    ):
        """Set payload metadata."""
        self.dom["resource"]["manifest"]["payload"][
            "installedDigest"
        ] = installed_digest
        self.dom["resource"]["manifest"]["payload"][
            "installedSize"
        ] = installed_size
        self.dom["resource"]["manifest"]["precursorDigest"] = precursor_digest

    def set_update_certificate(self, cert_data: bytes):
        """Set update certificate."""
        hash_ctx = hashlib.sha256()
        hash_ctx.update(cert_data)
        self.fingerprint = hash_ctx.digest()

    def set_image_signature(self, signature: bytes):
        """Set image signature."""

    def set_component_name(self, component: str):
        """Set component name."""
