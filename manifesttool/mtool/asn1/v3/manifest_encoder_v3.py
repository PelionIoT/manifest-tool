# ----------------------------------------------------------------------------
# Copyright 2019-2020 Pelion
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
import logging
from collections import OrderedDict
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native.encoder import encode as native_encoder

from manifesttool.mtool import ecdsa_helper
from manifesttool.mtool.asn1.manifest_codec import ManifestAsnCodecBase
from manifesttool.mtool.asn1.v3 import manifest_schema_v3 as manifest_schema


class ManifestAsnCodecV3(ManifestAsnCodecBase):
    VERSION = 'v3'

    logger = logging.getLogger('v3-manifest-codec')

    def __init__(self, dom=None):

        if dom:
            self.dom = dom
        else:
            self.dom = manifest_schema.Manifest()

    @classmethod
    def get_name(cls) -> str:
        return cls.VERSION

    def set_payload_version(self, version: str):
        assert isinstance(version, str)
        self.dom['payload-version'] = version

    def set_update_priority(self, priority: int):
        self.dom['update-priority'] = priority

    def set_vendor_id(self, vendor_id: bytes):
        self.dom['vendor-id'] = vendor_id

    def set_vendor_data(self, data: bytes):
        self.dom['vendor-data'] = data

    def set_class_id(self, class_id: bytes):
        self.dom['class-id'] = class_id

    def set_device_id(self, device_id: bytes):
        self.dom['device-id'] = device_id

    def set_payload_fingerprint(self, digest: bytes, size: int):
        self.dom['payload-digest'] = digest
        self.dom['payload-size'] = size

    def set_payload_uri(self, uri: str):
        self.dom['payload-uri'] = uri

    def set_payload_format(self, payload_format: str):
        self.dom['payload-format'] = payload_format

    def set_delta_metadata(
            self,
            installed_digest: bytes,
            installed_size: int,
            precursor_digest: bytes
    ):
        delta_meta_dom = manifest_schema.DeltaMetadata()
        delta_meta_dom['installed-size'] = installed_size
        delta_meta_dom['installed-digest'] = installed_digest
        delta_meta_dom['precursor-digest'] = precursor_digest
        self.dom['delta-metadata'] = delta_meta_dom

    @classmethod
    def decode(
            cls,
            data: bytes,
            verification_key: Optional[ec.EllipticCurvePublicKey]
    ) -> OrderedDict:

        signed_resource_dom = der_decoder.decode(
            data, asn1Spec=manifest_schema.SignedResource())[0]
        if not verification_key:
            return native_encoder(signed_resource_dom)

        codec = ManifestAsnCodecV3(dom=signed_resource_dom['manifest'])
        signed_data = codec.get_signed_data()
        der_signature = bytes(signed_resource_dom['signature'])
        signature = ecdsa_helper.signature_raw_to_der(der_signature)

        try:
            ecdsa_helper.ecdsa_verify(
                public_key=verification_key,
                signed_data=signed_data,
                signature=signature
            )
            cls.logger.info('Manifest Signature verified!')
        except InvalidSignature as ex:
            raise AssertionError(
                'Manifest Signature verification failed') from ex

        raw_image_signature = bytes(
            codec.dom['installed-signature'])
        if raw_image_signature:
            der_image_signature = \
                ecdsa_helper.signature_raw_to_der(
                    raw_image_signature
                )
            digest = bytes(codec.dom['payload-digest'])
            if str(codec.dom['payload-format']) == \
                    'arm-patch-stream':
                digest = bytes(
                    codec.dom['delta-metadata']['installed-digest']
                )
            try:
                ecdsa_helper.ecdsa_verify_prehashed(
                    public_key=verification_key,
                    digest=digest,
                    signature=der_image_signature
                )
                cls.logger.info('Image Signature verified!')
            except InvalidSignature as ex:
                raise AssertionError(
                    'Image Signature verification failed') from ex

        return native_encoder(signed_resource_dom)

    def get_signed_data(self) -> bytes:
        # sha_content = utils.sha_hash(enc_data)

        return der_encoder.encode(self.dom)

    def get_der_signed_resource(self, signature: bytes) -> bytes:
        resource_dom = manifest_schema.SignedResource()
        resource_dom['manifest-version'] = self.VERSION
        resource_dom['manifest'] = self.dom
        resource_dom['signature'] = signature
        return der_encoder.encode(resource_dom)

    def set_update_certificate(self, cert_data: bytes):
        raise NotImplementedError

    def set_image_signature(self, signature: bytes):
        self.dom['installed-signature'] = signature

    def set_component_name(self, component: str):
        self.dom['component-name'] = component
