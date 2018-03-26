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

from manifesttool.v1 import verify_signed_resource, verify_resource, verify_manifest_minimal, manifest_definition
from manifesttool import codec, utils, defaults

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric
import cryptography

# All supported decoders
from pyasn1.codec.der import decoder as der_decoder

LOG = logging.getLogger(__name__)

commonParameters = [
    'timestamp'
]

def certificateQuery(options, fingerprints, URLs):
    '''Load a certificate from a directory that contains certificates named by fingerprint'''
    cert = None
    missingCertURLs = []
    # Load defaults
    defaultConfig = {}
    if os.path.exists(defaults.config):
        with open(defaults.config) as f:
            defaultConfig = json.load(f)

    for i,fingerprint in enumerate(fingerprints):
        path = os.path.join(options.certificate_directory, fingerprint)
        LOG.debug('Fetching certificate: {}'.format(path))
        #look up the fingerprint
        cert = None
        if os.path.exists(path) and os.path.isfile(path):
            cert = path
            break
        else:
            LOG.debug('Could not find {}, checking default certificates'.format(path))
            defaultCertificateList = defaultConfig.get('default-certificates', [])
            for defaultCertificate in defaultCertificateList:
                if 'file' in defaultCertificate:
                    LOG.debug('Checking {} ...'.format(defaultCertificate['file']))
                    with open(defaultCertificate['file'], 'rb') as certfile:
                        cert_data = certfile.read()
                        x509cert = x509.load_der_x509_certificate(cert_data, default_backend())
                        fp = x509cert.fingerprint(hashes.SHA256())
                        if binascii.b2a_hex(fp) == fingerprint:
                            cert = certfile.name
                            break
                        else:
                            LOG.debug('Fingerprint mismatch for {}\n'
                                         'Expected: {}\n'
                                         'Actual:   {}'.format(certfile.name, fingerprint, binascii.b2a_hex(fp)))
            if cert:
                break

                    # load the certificate and check its fingerprint.
        if not cert:
            LOG.debug('Failed to find certificate: {}'.format(path))
    else:
        return None
    # TODO: Fetch missing certificates
    # TODO: Validate certificate chain

    LOG.debug('Found certificate: {}'.format(cert))
    return cert

def verifyManifestV1(options, data, signedResource, resource, manifest):
    if manifest['manifestVersion'] != 'v1':
        LOG.critical('Not a version 1 manifest')
        return None
    LOG.info('Manifest version {}: OK'.format(manifest['manifestVersion']))
    # Extract the crypto mode
    if 'oid' in manifest['encryptionMode']:
        LOG.critical('Cannot verify Object ID encryptionMode')
        return None

    if not 'enum' in manifest['encryptionMode']:
        LOG.critical('No encryptionMode specified')
        return None

    emode = manifest['encryptionMode']['enum']
    modes = verify_manifest_minimal.Manifest().getComponentType()['encryptionMode'].getType().getComponentType()['enum'].getType().getNamedValues()
    if modes.getValue(emode) != None and emode != modes.getName(0):
        LOG.info('Encryption mode {}: OK'.format(emode))
    else:
        LOG.critical('Encryption mode {} not supported'.format(emode))
        return None
    # NOTE: Currently only modes 1-3 are supported and these modes only allow SHA256.
    # This means that the manifest is hashed with SHA256.

    # Load defaults
    defaultConfig = {}
    if os.path.exists(defaults.config):
        with open(defaults.config) as f:
            defaultConfig = json.load(f)

    # Verify UUIDs
    for i in ['vendorId', 'classId', 'deviceId']:
        if i in manifest:
            try:
                LOG.debug('Found {}: {}'.format(i,manifest[i]))
                manifest_id = uuid.UUID(manifest[i])
            except:
                #if len(uuid) != 0 and len(uuid) != 128/8:
                LOG.critical('UUIDs ({}) must be 0 or 128 bits'.format(i))
                return None
            expect_id = None
            if hasattr(options,i) and getattr(options,i):
                expect_id = uuid.UUID(getattr(options,i))
            else:
                expect_id = defaultConfig.get(i, None)
                if expect_id:
                    expect_id = uuid.UUID(expect_id)
                    LOG.debug('Using default {} from {}'.format(i,defaults.config))
            if expect_id:
                if manifest_id != expect_id:
                    LOG.critical('UUID mismatch for {}\n'
                                 'Expected: {}\n'
                                 'Actual:   {}'.format(i, expect_id, manifest_id))
                    return None
                LOG.info('UUID {}: OK'.format(i))
            else:
                LOG.warning('UUID {} not specified; ignoring'.format(i))

    # Verify the manifest hash
    if not 'signature' in signedResource:
        LOG.critical('Signature missing, but encryption mode {} requires a signature'.format(emode))
        return None
    c_hash = utils.sha_hash(signedResource['resource'])
    if not 'hash' in signedResource['signature']:
        LOG.critical('Manifest does not contain a hash')
        return None
    e_hash = binascii.a2b_hex(signedResource['signature']['hash'])
    if c_hash != e_hash:
        LOG.critical('Hash mismatch\nExpected: {}\nActual:   {}'.format(binascii.b2a_hex(e_hash),binascii.b2a_hex(c_hash)))
        return None
    LOG.debug('Manifest hash: {}'.format(binascii.b2a_hex(c_hash)))
    LOG.info('Maninfest hash: OK')

    if not options.certificateQuery:
        LOG.warning('No certificateQuery provided, will not verify signatures')
    if (emode == 'none-ecc-secp256r1-sha256' or emode == 'aes-128-ctr-ecc-secp256r1-sha256') and options.certificateQuery:
        if not 'signatures' in signedResource['signature']:
            LOG.critical('Signature missing, but encryption mode {} requires a signature'.format(emode))
            return None
        for signature in signedResource['signature']['signatures']:
            if not 'certificates' in signature:
                LOG.critical('A certificate reference is mandatory in a signature')
                return None
            if len(signature['certificates']) == 0:
                LOG.critical('At least one certificate reference is mandatory in a signature')
                return None
            if not 'fingerprint' in signature['certificates'][0] or len(signature['certificates'][0]['fingerprint']) == 0:
                LOG.critical('A fingerprint is mandatory in a certificate')
                return None
            LOG.debug('Verifying signature by {}'.format(signature['certificates'][0]['fingerprint']))
            fingerprints = [x['fingerprint'] for x in signature['certificates']]
            URLs = [x['uri'] if 'uri' in x else '' for x in signature['certificates']]
            certfile = options.certificateQuery(options, fingerprints, URLs)
            if certfile == None: # TODO: Option for mandatory certificate verification
                if options.mandatory_signature:
                    LOG.critical('Could not find certificate chain matching {}'.format(fingerprints[0]))
                    return None
                LOG.warning('Could not find certificate chain matching {}'.format(fingerprints[0]))
            else:
                #if not options.ecdsaVerify(cert, signature):
                # ok = False
                # vk = ecdsa.VerifyingKey.from_pem(keypem)
                # ok = vk.verify(binascii.a2b_hex(signature['signature']),
                #           signedResource['resource'],
                #           hashfunc=hashlib.sha256,
                #           sigdecode=ecdsa.util.sigdecode_der)
                LOG.debug('Opening {} ...'.format(certfile))
                with open(certfile,'rb') as cert:
                    ok = options.ecdsaVerify(cert,signature['signature'],e_hash)
                    if not ok:
                        LOG.critical('Signature verification failed')
                        return None
                    LOG.info('Signature by {}: OK'.format(fingerprints[0]))


    # Decode the full manifest.
    full_manifest = {
        "der": lambda d: codec.bin2obj(data, manifest_definition.SignedResource(), der_decoder),
    }[options.encoding](data)
    LOG.debug('Parsed whole manifest from {}-encoded binary object'.format(options.encoding))

    full_manifest = full_manifest['resource']['resource']['manifest']
    # TODO: Measure nonce entropy
    if not 'nonce' in full_manifest:
        LOG.critical('A nonce is required in the manifest')
        return None
    else:
        nonce = binascii.a2b_hex(full_manifest['nonce'])
        if len(nonce)*8 != 128:
            LOG.critical('Nonce must be 128 bits. Got {}: {}'.format(len(nonce)*8, binascii.b2a_hex(nonce)))
            return None
    LOG.info('nonce: {} OK'.format(full_manifest['nonce']))

    # Call vendor-supplied Vendor Info Validator
    if hasattr(options, 'validateVendorInfo'):
        if options.validateVendorInfo(options, full_manifest['vendorInfo']):
            LOG.critical('Vendor Info Validation failed')
            return None
        LOG.info('VendorInfo: OK')

    # Extract apply period
    applyPeriod = full_manifest.get('applyPeriod')

    # must have either a payload or a dependency
    if not 'payload' in full_manifest and (
            not 'dependencies' in full_manifest or len(full_manifest['dependencies']) == 0):
        LOG.critical('Manifest must contain either a dependency or a payload')
        sys.exit(1)

    # Verify the payload
    if 'payload' in full_manifest:
        payload = full_manifest['payload']
        LOG.debug('Manifest contains a payload')
        # Verify the payload format
        if 'enum' in payload['format']:
            enum = payload['format']['enum']
            payloadFormats = manifest_definition.PayloadDescription().getComponentType()['format'].getType().getComponentType()['enum'].getType().getNamedValues()
            if payloadFormats.getValue(enum) == None or enum == payloadFormats.getName(0):
                LOG.critical('Payload format not recognized')
                return None
            LOG.info('Payload format {}: OK'.format(enum))
        elif 'objectId' in payload['format']:
            LOG.warning('Cannot verify Object ID payload format')
        else:
            LOG.critical('Payload does not contain a format')
            return None

        if emode == 'aes-128-ctr-ecc-secp256r1-sha256':
            if not 'encryptionInfo' in payload:
                LOG.critical('Encryption info must be present for encrypted payload distribution')
                return None
            cryptinfo = payload['encryptionInfo']
            # Validate the encryption information
            # Validate the init vector:
            if not 'initVector' in cryptinfo or len(binascii.a2b_hex(cryptinfo['initVector'])) != 128/8:
                LOG.critical('When using aes-128-ctr-ecc-secp256r1-sha256, a 128-bit AES initialization vector is mandatory')
                if 'initVector' in cryptinfo:
                    iv = binascii.a2b_hex(cryptinfo['initVector'])
                    LOG.critical('Expected 128 bits, got {}: {}'.format(len(iv)*8, binascii.b2a_hex(iv)))
                return None
            # TODO: Verify the entropy of the init vector

            # Determine the key mode
            kmode = 0
            # Options:
            if 'key' in cryptinfo['id'] and 'cipherKey' in cryptinfo['key']:
                if len(cryptinfo['key']['cipherKey']) == 0:
                    # Select a preshared local key
                    kmode = 1
                    LOG.debug('Using local preshared key for decryption')
                else:
                    # Select a preshared local key & decrypt a session key
                    kmode = 2
                    LOG.debug('Using local preshared key to decrypt the payload key')
            # Select certificate & decrypt a session key (Single-device only)
            elif 'certificate' in cryptinfo['id'] and 'cipherKey' in cryptinfo['key']:
                kmode = 3
                LOG.debug('Using ECDH to decrypt the device key')
            # Select a certificate & a keytable
            elif 'certificate' in cryptinfo['id'] and 'keyTable' in cryptinfo['key']:
                kmode = 4
                LOG.debug('Using ECDH to decrypt the payload key from the key table')

            if kmode == 0:
                LOG.critical('Unrecognized key distribution mode')
                return None

            # NOTE: It is not possible to verify payload without a device key when it is encrypted.
        # Verify the storage identifier
        if not 'storageIdentifier' in payload or len(payload['storageIdentifier']) == 0:
            LOG.critical('storageIdentifier must be provided')
            return None
        # Verify the resource reference
        if not 'reference' in payload:
            LOG.critical('A resource reference is mandatory in a payload-bearing manifest')
            return None
        if not 'hash' in payload['reference'] or len(payload['reference']['hash']) == 0:
            LOG.critical('A resource hash is mandatory in a payload reference')
            return None
        if not 'size' in payload['reference'] or payload['reference']['size'] == 0:
            LOG.critical('Zero-size resources are not permitted')
            return None

        if 'uri' in payload['reference']:
             LOG.debug('Payload refers to URI: {}'.format(payload['reference']['uri']))
             # TODO: verify payload URI

        # Do not verify the version string; it is for presentation only.

    # TODO: Validate aliases
    # TODO: Validate dependencies

    return {'timestamp':full_manifest['timestamp'], 'applyPeriod': applyPeriod}


def verifyManifest(options):
    data = options.input_file.read()
    LOG.debug('Read {} bytes of encoded data. Will try to decode...'.format(len(data)))

    # TODO: Verify the DER structure's encoding

    # Extract the signed resource.
    signed_resource_data = {
        "der": lambda d: codec.bin2obj(d, verify_signed_resource.SignedResource(), der_decoder),
    }[options.encoding](data)
    LOG.debug('Decoded SignedResource from {} encoded binary'.format(options.encoding))

    # Verify that the content *is* a manifest.
    # NOTE: This requires a parsing pass of the resource.
    resource_data = {
        "der": lambda d: codec.bin2obj(d, verify_resource.Resource(), der_decoder),
    }[options.encoding](signed_resource_data['resource'])
    LOG.debug('Decoded Resource from {} encoded binary'.format(options.encoding))

    if resource_data['resourceType'] != 'manifest':
        LOG.critical('The supplied file does not contain a manifest')
        return 1

    # Extract some relevant manifest information:
    manifest_data = {
        "der": lambda d: codec.bin2obj(d, verify_manifest_minimal.Manifest(), der_decoder),
    }[options.encoding](resource_data['resource'])
    LOG.debug('Decoded Manifest from {} encoded binary'.format(options.encoding))

    # Select a manifest format decoder based on the manifest version.
    def noVersionError(options, data, signedResource, resource, manifest):
        LOG.critical('Unsupported manifest version: {}'.format(manifest_data['manifestVersion']))
        None

    manifest_verification_data = {
        'v1': verifyManifestV1
    }.get(manifest_data['manifestVersion'],noVersionError)(options, data, signed_resource_data, resource_data, manifest_data)

    if manifest_verification_data == None:
        return 1

    # Verify the manifest timestamp is sane

    # The manifest timestamp should not be in the future, nor before the first release of this tool.
    # manifest_timestamp = decoded_data['resource']['resource']['manifest']['timestamp']
    manifest_timestamp = manifest_verification_data['timestamp']
    systime = int(time.time())
    if manifest_timestamp > systime:
        LOG.critical('Manifests MUST not be timestamped in the future.\n'
                     'Expected timestamp < {} ({})\n'
                     'Actual timestamp:    {} ({})'.format(
                     systime, time.ctime(systime), manifest_timestamp, time.ctime(manifest_timestamp)))

    release_time = time.mktime(time.strptime('2016-11-22T00:00:00',"%Y-%m-%dT%H:%M:%S"))
    if manifest_timestamp < int(release_time):
        LOG.critical('Manifests MUST not be timestamped before 2017.\n'
                     'Expected timestamp > {} ({})\n'
                     'Actual timestamp:    {} ({})'.format(
                     int(release_time), time.ctime(int(release_time)), manifest_timestamp, time.ctime(manifest_timestamp)))
    LOG.info('Timestamp {} < {} < {}: OK'.format(int(release_time), manifest_timestamp, systime))

    # Verify applyPeriod
    if 'applyPeriod' in manifest_verification_data and manifest_verification_data['applyPeriod']:
        applyPeriod = manifest_verification_data['applyPeriod']
        if release_time > applyPeriod['validFrom'] or \
                applyPeriod['validFrom'] > applyPeriod['validTo'] or \
                applyPeriod['validTo'] > systime:
            LOG.critical('Apply perion outside expected bounds: Expected:\n{} <= {} <= {} <= {}'.format(
                release_time, applyPeriod['validFrom'], applyPeriod['validTo'], systime
            ))
            return 1
        LOG.info('Apply period {} to {} OK'.format(applyPeriod['validFrom'], applyPeriod['validTo']))


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

def cryptographyEcdsaVerify(certfile, sig, sha):
    LOG.debug('Reading {}'.format(certfile.name))
    cert_data = certfile.read()
    cert = x509.load_der_x509_certificate(cert_data, default_backend())
    pubkey = cert.public_key()
    bsig = binascii.a2b_hex(sig)
    LOG.debug('Verifying...\n'
              'Signature: ({sigtype}){sig}\n'
              'Hash:      ({shatype}){sha}'.format(
              sigtype=type(bsig),sig=repr(bsig),shatype=type(sha),sha=repr(sha)))
    try:
        pubkey.verify(
            bsig,
            sha,
            asymmetric.ec.ECDSA(asymmetric.utils.Prehashed(hashes.SHA256()))
        )
    except cryptography.exceptions.InvalidSignature as e:
        return False
    return True


def main(options):

    options.ecdsaVerify = cryptographyEcdsaVerify

    if not options.certificate_directory:
        options.certificate_directory = defaults.certificatePath
    options.certificateQuery = certificateQuery
    options.mandatory_signature = True
    # if not hasattr(options, 'verifyScript'):

    return verifyManifest(options)
