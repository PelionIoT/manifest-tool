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

import json, logging, hashlib, time, sys, binascii, ecdsa, os, tempfile, uuid

from manifesttool import codec, utils, defaults
from manifesttool.v2 import cms_signed_data_definition
from manifesttool.v2 import manifest_definition

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography

# All supported decoders
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ

CMS_minimum_version = 5

LOG = logging.getLogger(__name__)

commonParameters = [
    'timestamp'
]

def certificateQuery(options, subjectKeyIdentifier):
    '''Load a certificate from a directory that contains certificates named by fingerprint'''
    cert = None
    missingCertURLs = []
    # Load defaults
    defaultConfig = {}
    if os.path.exists(defaults.config):
        with open(defaults.config) as f:
            defaultConfig = json.load(f)

    asciiSKI = binascii.b2a_hex(subjectKeyIdentifier)
    path = os.path.join(options.certificate_directory, asciiSKI)
    LOG.debug('Fetching certificate: {}'.format(path))
    #look up the subject key identifier
    cert = None
    if os.path.exists(path) and os.path.isfile(path):
        cert = path
    else:
        LOG.debug('Could not find {}, checking default certificates'.format(path))
        defaultCertificateList = defaultConfig.get('default-certificates', [])
        for defaultCertificate in defaultCertificateList:
            if 'file' in defaultCertificate:
                LOG.debug('Checking {} ...'.format(defaultCertificate['file']))
                with open(defaultCertificate['file'], 'rb') as certfile:
                    # load the certificate and check its subjectKeyIdentifier.
                    cert_data = certfile.read()
                    x509cert = x509.load_der_x509_certificate(cert_data, default_backend())
                    try:
                        ext = x509cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                    except cryptography.x509.ExtensionNotFound:
                        LOG.debug('Certificate {} does not contain SubjectKeyIdentifier.'.format(certfile.name))
                        return None

                    if ext.value.digest == subjectKeyIdentifier:
                        cert = certfile.name
                        break
                    else:
                        LOG.debug('Fingerprint mismatch for {}\n'
                                     'Expected: {}\n'
                                     'Actual:   {}'.format(certfile.name, asciiSKI, binascii.b2a_hex(ext.value.digest)))

    if not cert:
        LOG.debug('Failed to find certificate: {}'.format(path))
    # TODO: Validate certificate chain

    LOG.debug('Found certificate: {}'.format(cert))
    return cert

def verifyManifest(options):
    #
    # Verify each URL

    # Fetch each file from each listed URL (may not be possible, depending on network architecture)
    # Validate the hash of each file from each listed URL

    # Write to output buffer/file
    # indent = None if not options.pretty_json else 2
    # options.output_file.write(str.encode(json.dumps(decoded_data, indent = indent)))

    # If we're writing to TTY, add a helpful newline
    # if options.output_file.isatty():
    #     options.output_file.write(b'\n')

    return 0

def getDigestAlgorithm(alg):
    SupportedDigestAlgorithms = {
        '2.16.840.1.101.3.4.2.1' : hashes.SHA256()
    }
    return SupportedDigestAlgorithms.get(alg)

def getSignatureAlgorithm(alg):
    ecdsa_with_SHA256 = '1.2.840.10045.4.3.2'
    SupportedSignatureAlgorithms = {
        ecdsa_with_SHA256 : ec.ECDSA(hashes.SHA256()),
    }
    return SupportedSignatureAlgorithms.get(alg)


def verifyCMSSignedData(options, data):
    id_data = '1.2.840.113549.1.7.1'
    id_signedData = '1.2.840.113549.1.7.2'
    id_messageDigest = '1.2.840.113549.1.9.4'


    LOG.debug('Read {} bytes of encoded data. Will try to decode...'.format(len(data)))
    indent = None if not options.pretty_json else 4

    # import pdb; pdb.set_trace()
    decoded_CMS = {
        "der": lambda d: codec.bin2obj_native(d, cms_signed_data_definition.ContentInfo(), der_decoder),
    }[options.encoding](data)

    # Verify contentType
    if decoded_CMS['contentType'] == id_signedData:
        LOG.debug('contentType verified')
    else:
        LOG.critical('Unrecognized content type found in contentInfo.')
        return 1
    # Verify signedData version
    if decoded_CMS['content']['signedData']['version'] >= CMS_minimum_version:
        LOG.debug('Signed Data version verified')
    else:
        LOG.critical('Unsupported version of CMS Signed Data: {}'.format(decoded_CMS['content']['signedData']['version']))
    for alg in decoded_CMS['content']['signedData']['digestAlgorithms']:
        if not getDigestAlgorithm(alg['algorithm']):
            LOG.critical('Unsupported Digest Algorithm specified: {}'.format(alg))
            return 1
    LOG.debug('Digest Algorithms list verified.')
    if decoded_CMS['content']['signedData']['encapContentInfo']['eContentType'] == id_data:
        LOG.debug('eContentType verified')
    else:
        LOG.critical('Unrecognized content type found in encapContentInfo.')
        return 1
    idx = 0
    for sInfo in decoded_CMS['content']['signedData']['signerInfos']:
        # Check signer info version
        if sInfo['version'] >= CMS_minimum_version:
            LOG.debug('signerInfos[{}] CMS version verified'.format(idx))
        else:
            LOG.critical('In signerInfos[{}]: CMS Version {} not supported'.format(idx, sInfo['version']))
            return 1
        if not 'subjectKeyIdentifier' in sInfo['sid']:
            LOG.critical('Signers must be identified by subjectKeyIdentifier')
            return 1
        certpath = options.certificateQuery(options, sInfo['sid']['subjectKeyIdentifier'])
        if not certpath:
            return 1
        cert = None
        try:
            with open(certpath, 'rb') as f:
                cert = x509.load_der_x509_certificate(f.read(), default_backend())
        except ValueError as e:
            LOG.critical("X.509 Certificate Error in ({file}): {error}".format(error=e, file=cPath))
            return 1

        if not cert:
            LOG.critical('Could not load {}'.format(certpath))
            return 1

        alg = getSignatureAlgorithm(sInfo['signatureAlgorithm']['algorithm'])
        if not alg:
            LOG.critical('Signature algorithm not supported: {}'.format(sInfo['signatureAlgorithm']['algorithm']))
            return 1

        # Validate signature of signedAttrs
        signedAttrs = sInfo['signedAttrs']
        signature = sInfo['signature']
        # Encode the signedAttrs. This encoding MUST be DER according to the CMS RFC (RFC5652). The signature is calculated
        # with the DER tag value of 0x31 (SET OF). However, the data included in the final manifest has a DER tag with value
        # 0xA0 (IMPLICIT [0]). This must also be known at signature verification time.
        LOG.debug('Encoding signed attributes')
        options.encoding = options.encoding
        encoded_signedAttrs = utils.encode(signedAttrs, options, cms_signed_data_definition.SignedAttributes())
        try:
            cert.public_key().verify(signature, encoded_signedAttrs, alg)
        except cryptography.exceptions.InvalidSignature:
            LOG.critical('Signature verification failed')
            return 1
        LOG.debug('Signature by {} verified.'.format(binascii.b2a_hex(sInfo['sid']['subjectKeyIdentifier'])))

        # Get hash Attr
        hashAttr = None
        for sattr in signedAttrs:
            if sattr['attrType'] == id_messageDigest:
                hashAttr = sattr
        if not hashAttr:
            LOG.critical('The messageDigest signed attribute ({}) is mandatory for the manifest.'.format(id_messageDigest))
            return 1
        remoteDigest = {
            "der": lambda d: codec.bin2obj_native(d, univ.OctetString(), der_decoder),
        }[options.encoding](hashAttr['attrValues'][0])

        LOG.debug('Extracted message digest:  {}'.format(binascii.b2a_hex(remoteDigest)))


        # get the digest algorithm
        digestAlgorithmId = sInfo['digestAlgorithm']['algorithm']
        digestAlgorithm = getDigestAlgorithm(digestAlgorithmId)
        if not digestAlgorithm:
            LOG.critical('{} is not a supported digest algorithm'.format(digestAlgorithmId))
            return 1

        digestContext = hashes.Hash(digestAlgorithm, default_backend())
        digestContext.update(decoded_CMS['content']['signedData']['encapContentInfo']['eContent'])
        localDigest = digestContext.finalize()
        LOG.debug('Calculated message digest: {}'.format(binascii.b2a_hex(localDigest)))
        if localDigest != remoteDigest:
            LOG.critical('Signed message digest does not match digest of manifest.')
            LOG.critical('Expected: {}'.format(binascii.b2a_hex(remoteDigest)))
            LOG.critical('Actual:   {}'.format(binascii.b2a_hex(localDigest)))
            return 1
        LOG.info('Verified CMS manifest wrapper.')
    return 0


def main(options):
    # options.ecdsaVerify = cryptographyEcdsaVerify

    if not options.certificate_directory:
        options.certificate_directory = defaults.certificatePath
    options.certificateQuery = certificateQuery
    options.mandatory_signature = True
    # if not hasattr(options, 'verifyScript'):
    data = bytes(options.input_file.read())
    rc = verifyCMSSignedData(options, data)
    if rc:
        return rc
    # rc = verifyManifestV2(options, data)

    return rc
