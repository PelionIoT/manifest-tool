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

import logging, os, binascii, json
from manifesttool import verify
from manifesttool.v1 import verify_signed_resource as definition
from manifesttool import codec, utils, defaults
from manifesttool import signature_schema as schema
from manifesttool import create
# All supported decoders
from pyasn1.codec.der import decoder as der_decoder

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature
from cryptography import x509

LOG = logging.getLogger(__name__)

def sig_from_dict(d):
    certificates = []
    for cr in d['certificates']:
        certificates.append(schema.CertificateReference(
            fingerprint = binascii.a2b_hex(cr['fingerprint']),
                    uri = cr.get('uri','')
        ))
    return schema.SignatureBlock(
           signature = binascii.a2b_hex(d['signature']),
        certificates = certificates)

def sign(options):
    # Load defaults
    defaultConfig = {}
    if os.path.exists(defaults.config):
        with open(defaults.config) as f:
            defaultConfig = json.load(f)

    # Load the existing manifest
    content = None
    if hasattr(options, 'manifest') and options.manifest:
        options.manifest.seek(0)
        content = options.manifest.read()
    else:
        content = utils.download_file(options.url)

    # Extract the signed resource.
    signed_resource_data = {
        "der": lambda d: codec.bin2obj(d, definition.SignedResource(), der_decoder),
    }[options.encoding](content)
    if not signed_resource_data:
        return 1
    LOG.debug('Decoded SignedResource from {} encoded binary'.format(options.encoding))

    # Sign the resource
    # Calculate the hash of the content of the existing manifest
    c_hash = utils.sha_hash(signed_resource_data['resource'])
    if not 'hash' in signed_resource_data['signature']:
        LOG.critical('Manifest does not contain a hash')
        return None
    # Extract the hash
    e_hash = binascii.a2b_hex(signed_resource_data['signature']['hash'])
    # Compare calculated and extracted hashes
    if c_hash != e_hash:
        LOG.critical('Hash mismatch\nExpected: {}\nActual:   {}'.format(binascii.b2a_hex(e_hash),binascii.b2a_hex(c_hash)))
        return None
    LOG.debug('Manifest hash: {}'.format(binascii.b2a_hex(c_hash)))

    # Load a certificate and private key
    # Private key must be in .manifest_tool.json, or provided on the command-line

    # 1. Check the command-line
    if not hasattr(options,'private_key') or not options.private_key:
        # 2. Check the default config
        if 'private-key' in defaultConfig:
            try:
                # NOTE: binary is not specified since the key is usually PEM encoded.
                options.private_key = open(defaultConfig['private-key'],'r')
            except:
                LOG.critical('No private key specified and default key ({}) cannot be opened'.format(defaultConfig['private-key']))
                return 1
    # 3. Fail if the private key is not found
    if not hasattr(options, 'private_key') or not options.private_key:
        LOG.critical('No private key specified and default key ({}) cannot be opened'.format(defaultConfig['private-key']))
        return 1
    if not hasattr(options, 'password'):
        options.password = None

    # Load the private key
    privkey = load_pem_private_key(options.private_key.read(), password=options.password, backend=default_backend())

    # Make sure that this is an ECDSA key!
    if not isinstance(privkey, ec.EllipticCurvePrivateKey):
        LOG.critical('Private key was not an ECC private key')
        return 1
    LOG.debug('Loaded private key')
    LOG.info('Signing manifest...')
    # Create signature
    sig = privkey.sign(signed_resource_data['resource'], ec.ECDSA(hashes.SHA256()))
    LOG.debug('Signature: {}'.format(binascii.b2a_hex(sig)))

    # destroy the privkey object
    privkey = None

    # Certificate must be in .manifest_tool.json, or provided on the command-line
    # Load the certificate
    if not hasattr(options,'certificate') or not options.certificate:
        if 'default-certificates' in defaultConfig:
            options.certificate = open(defaultConfig['default-certificates'][0]['file'],'rb')

    if not hasattr(options,'certificate') or not options.certificate:
        LOG.critical('No certificate specified and default certificate ({}) cannot be opened'.format(defaultConfig['default-certificates'][0]['file']))
        return 1

    # Load the certificate object from the DER file
    certObj = None
    try:
        certObj = x509.load_der_x509_certificate(options.certificate.read(), default_backend())
    except ValueError as e:
        LOG.critical("X.509 Certificate Error in ({file}): {error}".format(error=e, file=options.certificate.name))
        return(1)

    if not certObj:
        LOG.critical("({file}) is not a valid certificate".format(file=cPath))
        return(1)

    # Make sure that the certificate is signed with SHA256
    if not isinstance(certObj.signature_hash_algorithm, hashes.SHA256):
        LOG.critical("In ({file}): Only SHA256 certificates are supported by the update client at this time.".format(file=cPath))
        return(1)

    LOG.info('Verifying signature with supplied certificate...')

    # Verify the signature with the provided certificate to ensure that the update target will be able to do so
    try:
        pubkey = certObj.public_key()
        pubkey.verify(sig, signed_resource_data['resource'], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        LOG.critical('New signature failed to verify with supplied certificate ({})'.format(options.certificate.name))
        return 1

    # Store the fingerprint of the certificate
    fingerprint = certObj.fingerprint(hashes.SHA256())

    certificates = []
    # for idx in range(len())
    #     certObj = None
    #     try:
    #         certObj = x509.load_der_x509_certificate(options.certificate.read(), default_backend())
    #     except ValueError as e:
    #         LOG.critical("X.509 Certificate Error in ({file}): {error}".format(error=e, file=options.certificate.name))
    #         return(1)
    #
    #     if not certObj:
    #         LOG.critical("({file}) is not a valid certificate".format(file=cPath))
    #         return(1)
    #     if not isinstance(certObj.signature_hash_algorithm, hashes.SHA256):
    #         LOG.critical("In ({file}): Only SHA256 certificates are supported by the update client at this time.".format(file=cPath))
    #         return(1)
    #     LOG.debug('Creating certificate reference ({}) from {} with fingerprint {}'.format(idx, options.certificate.name, fingerprint))
    LOG.debug('Creating certificate reference from {} with fingerprint {}'.format(options.certificate.name, fingerprint))
    uri = ''
    # TODO: Insert URI for delegation of trust
    cr = schema.CertificateReference(
        fingerprint = fingerprint,
        uri = uri
    )
    # Append the certificate reference to the current list
    # NOTE: Currently, only one certificate reference will exist in the certificates list, but with delegation of trust
    #       there will be more certificate references
    certificates.append(cr)
    LOG.debug('Signed hash ({}) of encoded content ({} bytes) with resulting signature {}'.format(
        binascii.b2a_hex(c_hash), len(content), binascii.b2a_hex(sig)))

    signatures = []
    for s in signed_resource_data['signature']['signatures']:
        signatures.append(sig_from_dict(s))

    # encode the signature block
    signatures.append(schema.SignatureBlock(signature = sig, certificates = certificates))

    # encode the resource signature
    resource_signature = schema.ResourceSignature(
            hash = c_hash,
            signatures = signatures
        )

    # encode the signed resource
    signed_resource = schema.SignedResource(
        resource = signed_resource_data['resource'],
        signature = resource_signature
    )

    # Convert the signed resource into a python dictionary
    manifest_dict = signed_resource.to_dict()
    # Encode the Python dictionary as a DER stream
    output = utils.encode(manifest_dict, options, definition.SignedResource())

    # Write the result to the output_file
    if hasattr(options, 'output_file') and options.output_file:
        # Write result to output file or stdout buffer.
        options.output_file.write(output)

        # Append newline if outputting to TTY
        if options.output_file.isatty():
            options.output_file.write(b'\n')
        return 0
    return 1

def main(options):
    if hasattr(options, 'manifest') and options.manifest:
        options.input_file = options.manifest
    if not hasattr(options, 'input_file') or not options.input_file:
        return 1
    rc = verify.main(options)
    if rc:
        return rc
    LOG.debug('Adding new signature to manifest')
    return sign(options)
