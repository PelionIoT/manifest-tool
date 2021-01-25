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
import abc
import base64
import hashlib
import logging
import re
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Optional
from typing import TypeVar

import yaml
from cryptography.hazmat.primitives.asymmetric import ec

from manifesttool.mtool.payload_format import PayloadFormat

READ_BLOCK_SIZE = 65536

ManifestAsnCodecBaseType = TypeVar(
    'ManifestAsnCodecBaseType', bound='ManifestAsnCodecBase')

logger = logging.getLogger('manifest-codec')

class ManifestAsnCodecBase(abc.ABC):

    @abc.abstractmethod
    def get_der_signed_resource(self, signature: bytes) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def get_signed_data(self) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def decode(
            cls,
            data: bytes,
            verification_key: Optional[ec.EllipticCurvePublicKey]
    ) -> OrderedDict:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def get_name() -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def set_payload_version(self, version):
        raise NotImplementedError

    @abc.abstractmethod
    def set_update_priority(self, priority: int):
        raise NotImplementedError

    @abc.abstractmethod
    def set_vendor_id(self, vendor_id: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_vendor_data(self, data: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_class_id(self, class_id: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_device_id(self, device_id: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_payload_fingerprint(self, digest: bytes, size: int):
        raise NotImplementedError

    @abc.abstractmethod
    def set_payload_uri(self, uri: str):
        raise NotImplementedError

    @abc.abstractmethod
    def set_payload_format(self, payload_format: str):
        raise NotImplementedError

    @abc.abstractmethod
    def set_delta_metadata(
            self,
            installed_digest: bytes,
            installed_size: int,
            precursor_digest: bytes
    ):
        raise NotImplementedError

    @abc.abstractmethod
    def set_update_certificate(self, cert_data: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_image_signature(self, signature: bytes):
        raise NotImplementedError

    @abc.abstractmethod
    def set_component_name(self, component: str):
        raise NotImplementedError

    def process_input_config(self, fw_version, input_cfg: dict) -> bytes:
        self.set_payload_version(fw_version)

        if 'priority' in input_cfg:
            self.set_update_priority(int(input_cfg['priority']))
        elif self.get_name() == 'v3':
            raise AssertionError('priority filed must be provided')

        self.set_component_name(input_cfg.get('component', 'MAIN'))

        vendor_id = self.encode_vendor_cfg(input_cfg)

        self.encode_device_cfg(input_cfg, vendor_id)

        return self._encode_payload_cfg(input_cfg)

    def _encode_payload_cfg(self, input_cfg) -> bytes:
        if 'payload' not in input_cfg:
            raise AssertionError('payload element not found')
        if 'file-path' in input_cfg['payload']:
            file_path = input_cfg['payload']['file-path']
            with open(file_path, 'rb') as fh:
                hash_ctx = hashlib.sha256()
                buf = fh.read(READ_BLOCK_SIZE)
                while buf:
                    hash_ctx.update(buf)
                    buf = fh.read(READ_BLOCK_SIZE)
                installed_digest = hash_ctx.digest()
                self.set_payload_fingerprint(
                    digest=installed_digest,
                    size=fh.tell()
                )
        else:
            raise AssertionError(
                'payload:file-path must be provided')
        if 'url' in input_cfg['payload']:
            self.set_payload_uri(input_cfg['payload']['url'])
        else:
            raise AssertionError('payload:url not found')
        if 'format' in input_cfg['payload']:
            try:
                payload_format = PayloadFormat(input_cfg['payload']['format'])
            except KeyError as ex:
                raise AssertionError('unknown payload-format') from ex
            self.set_payload_format(str(payload_format.value))
        else:
            raise AssertionError('payload-format element not found')

        if payload_format == PayloadFormat.PATCH:
            delta_file = Path(input_cfg['payload']['file-path'])
            delta_config_file = delta_file.with_suffix('.yaml')
            with delta_config_file.open('rb') as fh:
                delta_cfg = yaml.safe_load(fh)
            installed_digest = base64.b64decode(delta_cfg['installed-digest'])
            self.set_delta_metadata(
                installed_digest=installed_digest,
                installed_size=int(delta_cfg['installed-size']),
                precursor_digest=base64.b64decode(
                    delta_cfg['precursor-digest'])
            )
        return installed_digest

    def encode_device_cfg(self, input_cfg, vendor_id):
        if 'device' not in input_cfg:
            raise AssertionError('device element not found')
        if 'model-name' in input_cfg['device']:
            class_id = uuid.uuid5(vendor_id, input_cfg['device']['model-name'])
        elif 'class-id' in input_cfg['device']:
            class_id = uuid.UUID(input_cfg['device']['class-id'])
        else:
            raise AssertionError(
                'either device:class-id or device:model-name must be provided')
        logger.info('Class-ID: %s', class_id.bytes.hex())
        self.set_class_id(class_id.bytes)

    def encode_vendor_cfg(self, input_cfg):
        if 'vendor' not in input_cfg:
            raise AssertionError('invalid vendor element not found')
        if 'domain' in input_cfg['vendor']:
            if not re.match(r'^\S+\.\S+$', input_cfg['vendor']['domain']):
                raise AssertionError('invalid vendor_domain')
            vendor_domain = input_cfg['vendor']['domain']
            vendor_id = uuid.uuid5(uuid.NAMESPACE_DNS, vendor_domain)
        elif 'vendor-id' in input_cfg['vendor']:
            vendor_id = uuid.UUID(input_cfg['vendor']['vendor-id'])
        else:
            raise AssertionError(
                'either vendor:vendor-id or vendor:domain must be provided')

        logger.info('Vendor-ID: %s', vendor_id.bytes.hex())
        self.set_vendor_id(vendor_id.bytes)

        if 'vendor' in input_cfg and 'custom-data-path' in input_cfg['vendor']:
            self.set_vendor_data(
                Path(input_cfg['vendor']['custom-data-path']).read_bytes()
            )
        else:
            pass  # vendor data is an optional field
        return vendor_id
