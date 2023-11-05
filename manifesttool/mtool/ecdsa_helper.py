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
"""ECDSA helper file."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils
from cryptography.utils import int_to_bytes


def _load_ec_private_key(pem_key_data) -> ec.EllipticCurvePrivateKey:
    """Load EC PEM private key."""
    private_key = serialization.load_pem_private_key(
        pem_key_data, password=None, backend=default_backend()
    )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key
    raise TypeError()


def ecdsa_sign_prehashed(digest, pem_key_data) -> bytes:
    """ECDSA sign pre-hashed."""
    # pylint: disable=no-value-for-parameter
    private_key: ec.EllipticCurvePrivateKey
    private_key = _load_ec_private_key(pem_key_data)
    return private_key.sign(
        digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256()))
    )


def ecdsa_sign(data_to_sign, pem_key_data) -> bytes:
    """ECDSA sign."""
    # pylint: disable=no-value-for-parameter
    private_key = _load_ec_private_key(pem_key_data)
    return private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))


def public_key_from_private(pem_priv_key_data) -> ec.EllipticCurvePublicKey:
    """Extract public key from private."""
    private_key = serialization.load_pem_private_key(
        pem_priv_key_data, password=None, backend=default_backend()
    )
    return private_key.public_key()


def public_key_from_certificate(certificate_data) -> ec.EllipticCurvePublicKey:
    """Extract public key from the certificate."""
    cert = x509.load_der_x509_certificate(certificate_data, default_backend())
    return cert.public_key()


def public_key_from_bytes(public_key_data) -> ec.EllipticCurvePublicKey:
    """Encode public key from bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(), data=public_key_data
    )


def public_key_to_bytes(public_key) -> bytes:
    """Convert public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def signature_raw_to_der(raw_signature):
    """Encode raw signature to DER format."""
    return ec_utils.encode_dss_signature(
        r=int.from_bytes(raw_signature[:32], byteorder="big"),
        s=int.from_bytes(raw_signature[32:], byteorder="big"),
    )


def signature_der_to_raw(signature):
    """Convert DER signature to raw bytes."""
    # pylint: disable=invalid-name
    r, s = ec_utils.decode_dss_signature(signature)
    return int_to_bytes(r, 32) + int_to_bytes(s, 32)


def ecdsa_verify_prehashed(public_key, digest, signature):
    """Verify the pre-hashed signature."""
    public_key.verify(
        signature, digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256()))
    )


def ecdsa_verify(public_key, signed_data, signature):
    """Verify the signature."""
    public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
