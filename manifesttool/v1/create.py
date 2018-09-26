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
from __future__ import division
import codecs, hashlib, sys, json, os, base64, binascii, logging, ecdsa, uuid
from collections import namedtuple

# from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))

from cryptography.hazmat.primitives import ciphers as cryptoCiphers
from cryptography.hazmat.primitives import hashes as cryptoHashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat import backends as cryptoBackends
from cryptography import x509

from manifesttool import utils, codec, errorhandler, defaults
from manifesttool.v1.manifest_schema import SignedResource, Resource, ResourceSignature, ResourceReference, \
                                         Manifest, CertificateReference, PayloadDescription, ResourceAlias, \
                                         SignatureBlock, MacBlock
from manifesttool.v1 import manifest_definition
from manifesttool import keytable_pb2


# Import different encoders
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native import decoder as native_decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import OctetString, Sequence
from pyasn1.type import namedtype

from builtins import bytes

nonceSize = 16

LOG = logging.getLogger(__name__)

def manifestGet(manifest, path, shortpath = None):
    if shortpath:
        fieldValue = manifestGet(manifest, path = shortpath)
        if fieldValue:
            return fieldValue
    pathList = path.split('.')
    subManifest = manifest
    while subManifest and pathList:
        subManifest = subManifest.get(pathList[0])
        pathList = pathList[1:]
    if subManifest and not isinstance(subManifest, (str, bytes, int, bool, dict, list)):
        subManifest = str(subManifest)
    return subManifest

class cryptoMode:
    _mode = namedtuple('CryptoMode', 'name,symSize,hashSize,payloadEncrypt')
    MODES = {
        0: _mode('invalid', None, None, None),
        1: _mode('aes-128-ctr-ecc-secp256r1-sha256', 128/8, 256/8, True),
        2: _mode('none-ecc-secp256r1-sha256', 128/8, 256/8, False),
        3: _mode('none-none-sha256', 128/8, 256/8, False),
        4: _mode('none-psk-aes-128-ccm-sha256', 128/8, 256/8, False),
        5: _mode('psk-aes-128-ccm-sha256', 128/8, 256/8, True)
    }
    @staticmethod
    def name2enum(name):
        for k,v in cryptoMode.MODES.items():
            if v.name == name:
                return k
        else:
            return None
    def __init__(self, mode):
        m = self.MODES.get(mode)
        self.symSize = m.symSize
        self.hashSize = m.hashSize
        self.payloadEncrypt = m.payloadEncrypt
        self.name = m.name

def ARM_UC_mmCryptoModeShouldEncrypt(mode):
    return cryptoMode(mode).payloadEncrypt


def encryptClearText(cleartext, key, iv):
    backend = cryptoBackends.default_backend()
    iv_counter = int.from_bytes(bytes(iv), byteorder='big')
    # Create the cipher object
    cipher = cryptoCiphers.Cipher(cryptoCiphers.algorithms.AES(key), cryptoCiphers.modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    # Encrypt the plain text
    ciphertext = encryptor.update(bytes(cleartext)) + encryptor.finalize()
    return ciphertext

def encryptKeyAES(options, manifestInput, encryptionInfo, payload):
    # Store the PSK ID
    pskId = manifestGet(manifestInput, 'resource.resource.manifest.payload.encryptionInfo.id.key', 'encryptionKeyId')
    if not pskId:
        LOG.critical('The aes-psk encryption mode requires a "encryptionKeyId" entry in the input JSON file')
        sys.exit(1)
    encryptionInfo["id"] = { "key" : codecs.decode(pskId, 'hex')}
    secret = options.payload_secret

    # Read the secret
    secret_data = utils.read_file(secret) if os.path.isfile(secret) else base64.b64decode(secret)
    if not secret_data:
        LOG.critical('The aes-psk encryption mode requires either a base64-encoded secret or a valid file to be passed via the "-s" option.')
        sys.exit(1)

    # generate an IV
    IV = os.urandom(nonceSize)
    # generate a new key
    key = os.urandom(nonceSize)

    cipherpayload = encryptClearText(payload, key, IV)

    # NOTE: In general, ECB is a poor choice, since it fails quickly to known-plaintext attacks. In this case, however,
    # ECB should be appropriate, since the plaintext is precisely one AES block, and it is comprised of high entropy
    # random data; therefore, the plaintext is never known.

    # Create the cipher object
    cipher = cryptoCiphers.Cipher(cryptoCiphers.algorithms.AES(bytes(secret_data)),
                                  cryptoCiphers.modes.ECB(), backend=backend) # nosec ignore bandit B404
    keyEncryptor = cipher.encryptor()
    # Encrypt the plain text
    cipherKey = keyEncryptor.update(bytes(key)) + encryptor.finalize()
    return ciphertext

    return IV, cipherKey, cipherpayload

def get_payload_description(options, manifestInput):
    crypto_mode = manifestGet(manifestInput, 'resource.resource.manifest.encryptionMode.enum', 'encryptionMode')
    crypto_mode = crypto_mode if crypto_mode in cryptoMode.MODES else cryptoMode.name2enum(crypto_mode)
    if not crypto_mode:
        crypto_mode = get_crypto_mode(options, manifestInput)
    crypto_name = cryptoMode.MODES.get(crypto_mode).name

    payload_file = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.file', 'payloadFile')
    if hasattr(options, 'payload') and options.payload:
        payload_file = options.payload.name
    # payload URI defaults to the payload file path if no payload URI is supplied.
    payload_uri = payload_file
    payload_uri = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.uri', 'payloadUri')
    if hasattr(options, 'uri') and options.uri:
        payload_uri = options.uri

    dependencies = manifestGet(manifestInput, 'resource.resource.manifest.dependencies')
    if not any((payload_uri, payload_file)) and not dependencies:
        LOG.critical('No payload was specified and no dependencies were provided.')
        sys.exit(1)
        # fwFile/fwUri is optional, so if not provided we just return empty
        return None

    payload_hash = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.hash', 'payloadHash')
    payload_size = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.size', 'payloadSize')
    if payload_hash:
        LOG.debug('Found hash in input, skipping payload load. Hash: {}'.format(payload_hash))
        payload_hash = binascii.a2b_hex(payload_hash)
    else:
        if payload_file:
            payload_filePath = payload_file
            # If file path is not absolute, then make it relative to input file
            if os.path.isabs(payload_file) or not options.input_file.isatty():
                payload_filePath = os.path.join(os.path.dirname(options.input_file.name), payload_file)
            content = utils.read_file(payload_filePath)
        else:
            content = utils.download_file(payload_uri)

        # Read payload input, record length and hash it
        payload_size = len(content)
        payload_hash = utils.sha_hash(content)
        LOG.debug('payload of {} bytes loaded. Hash: {}'.format(payload_size, binascii.b2a_hex(payload_hash)))

    # Ensure the cryptoMode is valid
    if not crypto_mode in cryptoMode.MODES:
        valid_modes = ", ".join((('%s (%d)' % (v.name, k) for k, v in cryptoMode.MODES.items())))
        LOG.critical('Could not find specified cryptoMode (%d) in list of valid encryption modes. '
            'Please use on of the following: %r' % (crypto_mode, valid_modes))
        sys.exit(1)

    # Get encryption options for the provided mode
    should_encrypt = ARM_UC_mmCryptoModeShouldEncrypt(crypto_mode)
    if hasattr(options, 'encrypt_payload') and options.encrypt_payload and not should_encrypt:
        LOG.critical('--encrypt-payload specified, but cryptoMode({cryptoMode}) does not support encryption.'.format(**manifestInput))
        sys.exit(1)

    encryptionInfo = None
    if should_encrypt:
        LOG.debug('Crypto mode {} ({}) requires encryption. Will ensure ciphers are valid and loaded...'\
                .format(crypto_mode, crypto_name))
        if not options.encrypt_payload:
            LOG.critical('Specified crypto mode ({cryptoMode}) requires encryption, '
                        'but --encrypt-payload not specified.'.format(**manifestInput))
            sys.exit(1)
        cipherFile = manifestGet(manifestInput, 'resource.resource.manifest.payload.encryptionInfo.file', 'encryptedPayloadFile')
        if not cipherFile:
            LOG.critical('"resource.resource.manifest.payload.encryptionInfo.file" must be specified in the JSON input'
                        'file when --encrypt-payload is specified on the command-line.')
            sys.exit(1)
        encryptionInfo = {}

        cipherModes = {
                'aes-psk' : encryptKeyAES
        }

        if not options.encrypt_payload in cipherModes:
            LOG.critical('Specified encryption mode "{mode}" is not supported'.format(mode=options.encrypt_payload))
            sys.exit(1)

        init_vector, cipherKey, cipherpayload = cipherModes.get(options.encrypt_payload)(options, manifestInput, encryptionInfo, content)

        with open(cipherFile,'wb') as f:
            f.write(cipherpayload)

        encryptionInfo["key"] = { "cipherKey": cipherKey }
        encryptionInfo["initVector"] = init_vector
        LOG.debug('payload ({} bytes) encrypted. Cipher key: {}, cipher payload ouptut to : {}'.format(len(content), cipherKey, cipherFile))

    else:
        LOG.debug('Will not encrypt payload as crypto mode {} ({}) does not require it'.format(crypto_mode, crypto_name))

    return PayloadDescription(
        **{
            "storageIdentifier": manifestGet(manifestInput,'resource.resource.manifest.payload.storageIdentifier', 'storageIdentifier') or "default",
            "reference": ResourceReference(
                hash = payload_hash,
                uri = payload_uri,
                size = payload_size
            ),
            "encryptionInfo": encryptionInfo
        }
    )

def get_manifest_aliases(options, manifestInput):
    aliases = []
    for alias in manifestGet(manifestInput,'resource.resource.manifest.aliases') or []:
        # Ensure all required options are defined
        if not all(k in alias for k in ('file', 'uri')):
            LOG.critical('Could not create aliases, as all required keys for alias are not defined ("uri" and "file")')
            sys.exit(1)

        # Read alias file to calculate hash
        fPath = alias['file']
        if not os.path.isabs(fPath):
            fPath = os.path.join(os.path.dirname(options.input_file.name), fPath)
        content = utils.read_file(fPath)
        sha_hash = utils.sha_hash(content)
        LOG.debug('Creating ResourceAlias for file {} with SHA reference {}'.format(fPath, sha_hash))

        aliases.append(ResourceAlias(
            hash = sha_hash,
            uri = alias['uri']
        ))
    return aliases

def get_manifest_dependencies(options, manifestInput):
    dependencies = []
    for link in manifestGet(manifestInput, 'resource.resource.manifest.dependencies') or []:
        if not any(k in link for k in ('uri', 'file')):
            LOG.critical('Manifest link requires either a "uri" or a "file"'
                        'key - or both. Could only find %r' % link.keys())
            sys.exit(1)
        LOG.debug('Adding manifest link reference (URI: {}, File: {})'.format(link.get('uri', None), link.get('file', None)))

        # If file isn't provided, we attempt to download the file from provided URI
        # If the user provides the link as a filepath, just read the file
        if 'file' in link:
            linkPath = link['file']
            if not os.path.isabs(linkPath):
                linkPath = os.path.join(os.path.dirname(options.input_file.name), linkPath)
            content = utils.read_file(linkPath)
        else:
            content = utils.download_file(link['uri'])

        # Calculate the hash and length.
        manifest_hash = utils.sha_hash(content)
        manifest_length = len(content)
        LOG.debug('Linked manifest of {} bytes loaded. Hash: {}'.format(manifest_length, manifest_hash))

        link_uri = link['uri'] if 'uri' in link else link['file']
        dependencies.append({
            'hash': manifest_hash,
            'uri': link_uri,
            'size': manifest_length
        })
    return dependencies

def get_crypto_mode(options, manifestInput):
    crypto_mode = manifestGet(manifestInput, 'resource.resource.manifest.encryptionMode.enum', 'encryptionMode')
    crypto_mode = crypto_mode if crypto_mode in cryptoMode.MODES else cryptoMode.name2enum(crypto_mode)
    if not crypto_mode:
        isEncrypted = hasattr(options, 'encrypt_payload') and options.encrypt_payload
        isMAC = hasattr(options, 'mac') and options.mac

        if isEncrypted and isMAC:
            cryptname = 'psk-aes-128-ccm-sha256'
        if not isEncrypted and isMAC:
            cryptname = 'none-psk-aes-128-ccm-sha256'
        if not isEncrypted and not isMAC:
            cryptname = 'none-ecc-secp256r1-sha256'
        if isEncrypted and not isMAC:
            cryptname = 'aes-128-ctr-ecc-secp256r1-sha256'
        crypto_mode = cryptoMode.name2enum(cryptname)

    return crypto_mode

def get_manifest(options, manifestInput):
    vendor_info = manifestGet(manifestInput, 'resource.resource.manifest.vendorInfo', 'vendorInfo') or b""
    vendor_id = manifestGet(manifestInput, 'resource.resource.manifest.vendorId', 'vendorId')
    device_id = manifestGet(manifestInput, 'resource.resource.manifest.deviceId', 'deviceId')
    class_id = manifestGet(manifestInput, 'resource.resource.manifest.classId', 'classId')

    if not device_id and not (vendor_id and class_id):
        LOG.critical('Input file must contain either Device ID, or both Vendor and Class IDs, or all three\n'
            'deviceId:"{}"\nvendorId:"{}"\nclassId:"{}"'.format(device_id, vendor_id, class_id))
        sys.exit(1)

    validTo = manifestGet(manifestInput, 'resource.resource.manifest.applyPeriod.validTo', 'applyPeriod.validTo')
    validFrom = manifestGet(manifestInput, 'resource.resource.manifest.applyPeriod.validFrom', 'applyPeriod.validFrom')
    applyPeriod = None
    if validTo or validFrom:
        applyPeriod = {
            'validFrom' : validFrom,
            'validTo'   : validTo,
        }

    crypto_mode = { 'enum' : get_crypto_mode(options, manifestInput) }
    nonce = manifestGet(manifestInput, 'resource.resource.manifest.nonce')
    if nonce:
        nonce = binascii.a2b_hex(nonce)
    else:
        nonce = os.urandom(nonceSize)
    if not manifestGet(manifestInput, 'resource.resource.manifest.applyImmediately', 'applyImmediately'):
        LOG.warning('applyImmediately is currently ignored by the update client; manifests are always applied immediately.')
    return Manifest(
        manifestVersion = manifestGet(manifestInput,'resource.resource.manifest.version'),
        vendorInfo = vendor_info,
        vendorId = uuid.UUID(vendor_id).bytes if vendor_id else b'',
        classId = uuid.UUID(class_id).bytes if class_id else b'',
        deviceId = uuid.UUID(device_id).bytes if device_id else b'',
        nonce = nonce,
        applyImmediately = manifestGet(manifestInput, 'resource.resource.manifest.applyImmediately', 'applyImmediately'),
        applyPeriod = applyPeriod,
        encryptionMode = crypto_mode,
        description = manifestGet(manifestInput, 'resource.resource.manifest.description', 'description'),
        aliases = get_manifest_aliases(options, manifestInput),
        payload = get_payload_description(options, manifestInput),
        dependencies = get_manifest_dependencies(options, manifestInput),
        timestamp = manifestGet(manifestInput, 'resource.resource.manifest.timestamp')
    )

def getDevicePSKData(mode, psk, nonce, digest, payload_key):
    crypto_mode = cryptoMode(mode)
    LOG.debug('Creating PSK data: ')
    LOG.debug('    mode: {}'.format(crypto_mode.name))
    LOG.debug('    iv  ({0} bytes): {1}'.format(len(nonce), binascii.b2a_hex(nonce)))
    LOG.debug('    md  ({0} bytes): {1}'.format(len(digest), binascii.b2a_hex(digest)))

    data = {'hash':str(digest)}
    if payload_key:
        data['cek'] = payload_key
    asnData = native_decoder.decode(data, asn1Spec=manifest_definition.KeyTableEntry())
    # print(asnData)

    plainText = der_encoder.encode(asnData)
    LOG.debug('PSK plaintext ({0} bytes): {1}'.format(len(plainText), binascii.b2a_hex(plainText)))

    pskSig = {
        'none-psk-aes-128-ccm-sha256': lambda key, iv, d: AESCCM(key[:128//8]).encrypt(iv, d, b''),
        'psk-aes-128-ccm-sha256': lambda key, iv, d: AESCCM(key[:128//8]).encrypt(iv, d, b'')
    }.get(crypto_mode.name, lambda a,b,d: None)(psk, nonce, plainText)
    LOG.debug('PSK data ({0} bytes): {1}'.format(len(pskSig), binascii.b2a_hex(pskSig)))
    return pskSig

def symmetricArgsOkay(options):
    okay = hasattr(options, 'private_key') and options.private_key
    # okay = okay and hasattr(options, 'psk_table_encoding') and options.psk_table_encoding
    if hasattr(options, 'psk_table_encoding') and options.psk_table_encoding:
        okay = okay and True
    okay = okay and hasattr(options, 'psk_table') and options.psk_table
    return okay

def isPsk(mode):
    crypto_mode = cryptoMode(mode)
    return {
        'aes-128-ctr-ecc-secp256r1-sha256' : False,
        'none-ecc-secp256r1-sha256':False,
        'none-none-sha256': False,
        'none-psk-aes-128-ccm-sha256': True,
        'psk-aes-128-ccm-sha256': True
    }.get(crypto_mode.name)

def get_symmetric_signature(options, manifestInput, enc_data):
    input_hash = manifestGet(manifestInput,'signature.hash') or b''

    # There should always be a signing key on create.
    if not hasattr(options,'private_key') or not options.private_key:
        if 'psk-master-key' in manifestInput:
            try:
                options.private_key = open(manifestInput['psk-master-key'],'rb')
            except:
                LOG.critical('No PSK master key specified and default key ({}) cannot be opened'.format(manifestInput['private-key']))
                sys.exit(1)
        else:
            LOG.critical('Resource is not signed and no PSK master key is provided.')
            sys.exit(1)

    if not symmetricArgsOkay(options):
        LOG.critical('--mac requires:')
        LOG.critical('    --private-key: The master key for generating device PSKs')
        #                                                                                 80 chars ->|
        #             ================================================================================
        LOG.critical('    --psk-table: the output file for PSKs. This argument is optional/ignored')
        LOG.critical('                 when inline encoding is used.')
        LOG.critical('    --psk-table-encoding: the encoding to use for the PSK output file.')
        LOG.critical('    Either:')
        LOG.critical('        --device-urn: The device URN for the target device (Endpoint Client Name)')
        LOG.critical('    OR:')
        LOG.critical('        --filter-id: The filter identifier used to gather device URNs')
        sys.exit(1)

    # Get SHA-256 hash of content and sign it using private key
    sha_content = utils.sha_hash(enc_data)
    # If a hash is provided in the input json, then the encoded content must match the provided hash
    if input_hash and sha_content != binascii.a2b_hex(input_hash):
        LOG.critical('Manifest hash provided in input file does not match hashed output')
        LOG.critical('Expected: {0}'.format(input_hash))
        LOG.critical('Actual:   {0}'.format(binascii.b2a_hex(sha_content)))
        sys.exit(1)

    # Load a default URN out of the settings file.
    devices = manifestGet(manifestInput,'deviceURNs') or []
    LOG.info('Loaded device URNs from {!r}'.format(defaults.config))
    for dev in devices:
        LOG.info('    {!r}'.format(dev))

    # Optionally load a URN out of the command-line arguments
    if hasattr(options, 'device_urn') and options.device_urn:
        cmdDevs = [options.device_urn]
        LOG.info('Loaded device URNs from input arguments')
        for dev in cmdDevs:
            LOG.info('    {!r}'.format(dev))
        devices.extend(cmdDevs)
    if hasattr(options, 'filter_id') and options.filter_id:
        LOG.critical('Device Filters not supported yet.')
        sys.exit(1)

    # Use only unique devices
    devices = list(set(devices))

    crypto_mode = get_crypto_mode(options, manifestInput)

    payload_key = b''
    if hasattr(options, 'payload_key') and options.payload_key:
        LOG.debug('Converting payload key ({0}) to binary'.format(options.payload_key))
        payload_key = bytes(binascii.a2b_hex(options.payload_key))
    LOG.debug('Payload key length: {0}'.format(len(payload_key)))
    master_key = options.private_key.read()
    vendor_id = manifestGet(manifestInput, 'resource.resource.manifest.vendorId', 'vendorId')
    class_id = manifestGet(manifestInput, 'resource.resource.manifest.classId', 'classId')
    iv = os.urandom(13)
    deviceSymmetricInfos = {}
    # For each device
    maxIndexSize = 0
    maxRecordSize = 0
    LOG.info('Creating per-device validation codes...')
    for device in devices:
        LOG.info('    {!r}'.format(device))

        hkdf = utils.getDevicePSK_HKDF(cryptoMode(crypto_mode).name, master_key, uuid.UUID(vendor_id).bytes, uuid.UUID(class_id).bytes, b'Authentication')
        psk = hkdf.derive(bytes(device, 'utf-8'))
        maxIndexSize = max(maxIndexSize, len(device))
        # Now encrypt the hash with the selected AE algorithm.
        pskCipherData = getDevicePSKData(crypto_mode, psk, iv, sha_content, payload_key)
        recordData = der_encoder.encode(OctetString(hexValue=binascii.b2a_hex(pskCipherData).decode("ascii")))
        maxRecordSize = max(maxRecordSize, len(recordData))
        deviceSymmetricInfos[device] = recordData
    # print (deviceSymmetricInfos)
    def proto_encode(x):
        keytable = keytable_pb2.KeyTable()

        for k, d in x.items():
            entry = keytable.entries.add()
            entry.urn = k
            entry.opaque = d
        return keytable.SerializeToString()
    # Save the symmetric info file
    encodedSymmertricInfos = {
        'json' : lambda x : json.JSONEncoder(default=binascii.b2a_base64).encode(x),
        'cbor' : lambda x : None,
        'protobuf': proto_encode,
        'text' : lambda x : '\n'.join([','.join([binascii.b2a_hex(y) for y in (k,d)]) for k, d in x.items()]) + '\n'
        # 'inline' : lambda x : None
    }.get(options.psk_table_encoding)(deviceSymmetricInfos)
    options.psk_table.write(encodedSymmertricInfos)

    #=========================
    # PSK ID is the subject key identifier (hash) of the master key.
    # The URI of the "certificate" is the location at which to find the key table or key query.
    # PSK is known only to the signer and the device
    # PSK Signature is AE(PSK, hash), but it is not included, since it must be distributed in the key table.
    shaMaster = cryptoHashes.Hash(cryptoHashes.SHA256(), cryptoBackends.default_backend())
    shaMaster.update(master_key)
    subjectKeyIdentifier = shaMaster.finalize()

    mb = MacBlock(   pskID = subjectKeyIdentifier,
                keyTableIV = iv,
               keyTableRef = 'thismessage://1',
           keyTableVersion = 0,
        keyTableRecordSize = maxRecordSize,
         keyTableIndexSize = maxIndexSize
    )
    macs=[mb]
    rs = ResourceSignature(
            hash = sha_content,
            signatures = [],
            macs = macs)
    return rs


def get_signature(options, manifestInput, enc_data):
    signatures = manifestGet(manifestInput,'signature.signatures') or []
    input_hash = manifestGet(manifestInput,'signature.hash') or b''

    # There should always be a signing key on create.
    if not hasattr(options,'private_key') or not options.private_key:
        if 'private-key' in manifestInput:
            try:
                options.private_key = open(manifestInput['private-key'],'r')
            except:
                LOG.critical('No private key specified and default key ({}) cannot be opened'.format(manifestInput['private-key']))
                sys.exit(1)
        else:
            LOG.critical('Resource is not signed and no signing key is provided.')
            sys.exit(1)

    # Get SHA-256 hash of content and sign it using private key
    sha_content = utils.sha_hash(enc_data)
    if len(signatures):
        # If a signature is provided in the input json, then the encoded content must match the provided hash
        # Signature validation is not performed, since this would require certificate acquisition, which may not be
        # possible
        if sha_content != binascii.a2b_hex(input_hash):
            LOG.critical('Manifest hash provided in input file does not match hashed output')
            LOG.critical('Expected: {0}'.format(input_hash))
            LOG.critical('Actual:   {0}'.format(binascii.b2a_hex(sha_content)))
            sys.exit(1)
        # TODO: perform best-effort signature validation

    if hasattr(options, 'private_key') and options.private_key:
        sk = ecdsa.SigningKey.from_pem(options.private_key.read())
        sig = sk.sign_digest(sha_content, sigencode=ecdsa.util.sigencode_der)

        certificates = []

        # pick a signature block with no signature in it.
        inputCerts = manifestGet(manifestInput, 'certificates') or []

        # If no certificate was provided in the manifest input or in options,
        if len(inputCerts) == 0:
            # then load the default certificate
            inputCerts = manifestInput.get('default-certificates', [])

        # If there is still no certificate,
        if len(inputCerts) == 0:
            # Search through all signature blocks for one that contains certificates but no signature
            for idx, sb in enumerate(signatures):
                 if not 'signature' in sb:
                     inputCerts = sb.get('certificates', [])
                     # This signature will be appended later so we must trim it.
                     del signatures[idx]
                     break

        for idx, cert in enumerate(inputCerts):
            if not any(k in cert for k in ('file', 'uri')):
                LOG.critical('Could not find "file" or "uri" property for certificate')
                sys.exit(1)

            # If 'file', we just use the content in local file
            if 'file' in cert:
                fPath = cert['file']
                if not os.path.isabs(fPath):
                    fPath = os.path.join(os.path.dirname(options.input_file.name), cert['file'])
                content = utils.read_file(fPath)

            # Else we download the file contents
            else:
                content = utils.download_file(cert['uri'])
            # Figure our which extension the certificate has
            contentPath = cert['file'] if 'file' in cert else cert['uri']
            ext = contentPath.rsplit('.', 1)[1]

            # Read the certificate file, and get DER encoded data
            if ext == 'pem':
                lines = content.replace(" ",'').split()
                content = binascii.a2b_base64(''.join(lines[1:-1]))

            # Verify the certificate hash algorithm
            # Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
            # fingerprint = utils.sha_hash(content)
            cPath = cert['file'] if 'file' in cert else cert['uri']
            certObj = None
            try:
                certObj = x509.load_der_x509_certificate(content, cryptoBackends.default_backend())
            except ValueError as e:
                LOG.critical("X.509 Certificate Error in ({file}): {error}".format(error=e, file=cPath))
                sys.exit(1)

            if not certObj:
                LOG.critical("({file}) is not a valid certificate".format(file=cPath))
                sys.exit(1)
            if not isinstance(certObj.signature_hash_algorithm, cryptoHashes.SHA256):
                LOG.critical("In ({file}): Only SHA256 certificates are supported by the Mbed Cloud Update client at this time.".format(file=cPath))
                sys.exit(1)
            fingerprint = certObj.fingerprint(cryptoHashes.SHA256())

            LOG.debug('Creating certificate reference ({}) from {} with fingerprint {}'.format(idx, contentPath, fingerprint))
            uri = ''
            if 'uri' in cert:
                uri = cert['uri']
            certificates.append(CertificateReference(
                fingerprint = fingerprint,
                uri = uri
            ))

        LOG.debug('Signed hash ({}) of encoded content ({} bytes) with resulting signature {}'.format(
            sha_content, len(enc_data), sig))
        signatures.append(SignatureBlock(signature = sig, certificates = certificates))
    return ResourceSignature(
            hash = sha_content,
            signatures = signatures
        )

def create_signed_resource(options):
    # Read options from manifest input file/
    # if (options.input_file.isatty()):
    #     LOG.info("Reading data from from active TTY... Terminate input with ^D")
    manifestInput = {
        'applyImmediately' : True
    }

    try:
        if os.path.exists(defaults.config):
            with open(defaults.config) as f:
                manifestInput.update(json.load(f))
        if not options.input_file.isatty():
            content = options.input_file.read()
            if content and len(content) >= 2: #The minimum size of a JSON file is 2: '{}'
                manifestInput.update(json.loads(content))
    except ValueError as e:
        LOG.critical("JSON Decode Error: {}".format(e))
        sys.exit(1)

    # Create the Resource structure first, and encode it using specified encoding scheme
    # This encoded data will then be used for signing
    try:
        resource = Resource(
            resource = get_manifest(options, manifestInput),
            resourceType  = Resource.TYPE_MANIFEST
        )
    except errorhandler.InvalidObject as err:
        LOG.critical('Unable to create resource object: {0}'.format(err))
        sys.exit(1)

    # Convert the Python object to a Python dictionary, and then encode to
    # specified encoding format
    resource_encoded = utils.encode(resource.to_dict(), options, manifest_definition.Resource())

    signature = None
    crypto_mode = get_crypto_mode(options, manifestInput)
    if isPsk(crypto_mode):
        signature = get_symmetric_signature(options, manifestInput, enc_data = resource_encoded)
    else:
        signature = get_signature(options, manifestInput, enc_data = resource_encoded)
    try:
        sresource = SignedResource(
            resource = resource,
            signature = signature
        )
        return sresource.to_dict()
    except errorhandler.InvalidObject as err:
        LOG.critical('Unable to create signed resource: {0}'.format(err))
        sys.exit(1)

def toCfile(varname, data, colwidth=120, indentsize=4):
    s  = '#include <stdint.h>\n'
    s += 'uint8_t {}[] = {{\n'.format(varname)
    xl = ['{0:#04x}'.format(b) for b in bytes(data)]
    # w = (ax + b*(x-1))
    # w = ax + bx - b
    # (w + b) / (a + b)
    rowcount = int((colwidth - indentsize + len(', ') - len(',')) / len(', 0x00'))
    while len(xl):
        rownum = min(rowcount,len(xl))
        row = '    ' + ', '.join(xl[:rownum])
        if len(xl) > rownum:
            row += ','
        xl = xl[rownum:]
        row += '\n'
        s += row;
    s += '};\n'
    return codecs.encode(s, 'utf8')

def write_result(data, options):
    if hasattr(options,'hex') and options.hex:
        LOG.debug('Converting binary data into hex encoded string')
        data = codecs.encode(data, 'hex')
    if hasattr(options,'c_file') and options.c_file:
        LOG.debug('Converting binary data into a C file.')
        data = toCfile('manifest', data)

    # Write result to output file or stdout buffer.
    options.output_file.write(data)

    # Append newline if outputting to TTY
    if hasattr(options, 'output_file') and options.output_file.isatty():
        options.output_file.write(b'\n')

def main(options):
    LOG.debug('Creating new manifest from input file and options')

    # Parse input files and options. Generate hydrated and hierachial manifest JSON.
    manifest = create_signed_resource(options)
    LOG.debug('Manifest python object successfully created from ASN.1 definition and input')

    # Encode data if requested
    output = utils.encode(manifest, options, manifest_definition.SignedResource())
    LOG.debug('Manifest successfully encoded into desired format ({}). Size: {} bytes.'.format(options.encoding, len(output)))

    if hasattr(options, 'mac') and options.mac and options.psk_table_encoding == 'inline':
        output += options.psk_table

    # And we're done
    write_result(output, options)
