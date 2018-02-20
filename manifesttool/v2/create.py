# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2017 -*-
# -*- copyright-comment-string: # -*-
import codecs, sys, json, os, base64, binascii, logging, uuid
import time
from collections import namedtuple

# from pyasn1 import debug
# debug.setLogger(debug.Debug('all'))

from cryptography.hazmat.primitives import ciphers as cryptoCiphers
from cryptography.hazmat.primitives import hashes as cryptoHashes
from cryptography.hazmat.primitives import serialization as keyserdes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat import backends as cryptoBackends
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
import cryptography.exceptions

from manifesttool import utils, codec, errorhandler, defaults
from manifesttool.v2 import cms_signed_data_definition
from manifesttool.v2 import manifest_definition

# Import different encoders
from pyasn1.type import univ

from builtins import bytes

LOG = logging.getLogger(__name__)

def calculate_hash(options, m):
    md = cryptoHashes.Hash(cryptoHashes.SHA256(), backend=cryptoBackends.default_backend())
    md.update(m)
    return md.finalize()

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

def mkOIDtuple(s):
    return tuple(map(int, s.split('.')))

def mkCondition(options, name, value, valtype):
    return {'type': name, 'value' : { valtype : value}}

def get_conditions(options, manifestInput):

    conditions = []
    vendorId = manifestGet(manifestInput, 'resource.resource.manifest.vendorId', 'vendorId')
    classId = manifestGet(manifestInput, 'resource.resource.manifest.classId', 'classId')
    deviceId = manifestGet(manifestInput, 'resource.resource.manifest.deviceId', 'deviceId')
    applyBefore = manifestGet(manifestInput, 'resource.resource.manifest.applyPeriod.validTo', 'applyPeriod.validTo')
    vendorInfo = manifestGet(manifestInput, 'resource.resource.manifest.vendorInfo', 'vendorInfo')
    if vendorId:
        conditions.append(mkCondition(options, 'vendorId', uuid.UUID(vendorId).bytes, 'raw'))
    if classId:
        conditions.append(mkCondition(options, 'classId', uuid.UUID(classId).bytes, 'raw'))
    if deviceId:
        conditions.append(mkCondition(options, 'deviceId', uuid.UUID(deviceId).bytes, 'raw'))
    if applyBefore:
        conditions.append(mkCondition(options, 'applyBefore', applyBefore, 'int'))
    if vendorInfo:
        conditions.append(mkCondition(options, 'vendorSpecific', vendorSpecific, 'raw'))

    return conditions

def mkDirective(options, name, rule, ruleType):
    return {'type': name, 'rule' : {ruleType: rule}}

def get_directives(options, manifestInput):
    directives = []
    applyBefore = manifestGet(manifestInput, 'resource.resource.manifest.applyPeriod.validTo', 'applyPeriod.validTo')
    if applyBefore:
        directives.append(mkDirective(options,'applyBefore', applyBefore, 'int'))
    applyImmediately = manifestGet(manifestInput, 'resource.resource.manifest.applyImmediately', 'applyImmediately')
    if applyImmediately != None:
        directives.append(mkDirective(options,'applyImmediately', applyImmediately, 'bool'))
    vendorSpecific = manifestGet(manifestInput, 'resource.resource.manifest.vendorDirective', 'vendorDirective')
    if vendorSpecific:
        directives.append(mkDirective(options,'vendorSpecific', vendorSpecific, 'raw'))

    return directives

def get_aliases(options, manifestInput):
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

def get_dependencies(options, manifestInput):
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
        manifest_hash = utils.calculate_hash(options, content)
        manifest_length = len(content)
        LOG.debug('Linked manifest of {} bytes loaded. Hash: {}'.format(manifest_length, binascii.b2a_hex(manifest_hash)))

        link_uri = link['uri'] if 'uri' in link else link['file']
        dependencies.append({
            'hash': manifest_hash,
            'uri': link_uri,
            'size': manifest_length
        })
    return dependencies

def get_payload_info(options, manifestInput):
    encryptionInfo = None
    content = None
    payload_file = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.file', 'payloadFile')
    if hasattr(options, 'payload') and options.payload:
        payload_file = options.payload.name
    # payload URI defaults to the payload file path if no payload URI is supplied.
    payload_uri = payload_file
    payload_uri = manifestGet(manifestInput, 'resource.resource.manifest.payload.reference.uri', 'payloadUri')
    if hasattr(options, 'uri') and options.uri:
        payload_uri = options.uri

    if not any((payload_uri, payload_file)):
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
        payload_hash = utils.calculate_hash(options, content)
        LOG.debug('payload of {} bytes loaded. Hash: {}'.format(payload_size, binascii.b2a_hex(payload_hash)))

    payloadChoice = {}
    if hasattr(options, 'integrated_payload') and options.integrated_payload:
        payloadChoice['integrated'] = content
    else:
        payloadChoice['reference'] = {
            'hash' : payload_hash,
            'uri'  : payload_uri
        }

    if 'reference' in payloadChoice:
        if not 'uri' in payloadChoice['reference'] or not payloadChoice['reference']['uri']:
            LOG.critical('A URI must be provided when a payload reference is used.')
            return 1

    payloadInfo = {
        'format' : {
            'enum' : 'rawBinary'
        },
        'storageIdentifier' : manifestGet(manifestInput,'resource.resource.manifest.payload.storageIdentifier', 'storageIdentifier') or '0',
        'size' : payload_size,
        'payload' : payloadChoice
    }
    if encryptionInfo:
        payloadInfo['encryptionInfo'] = encryptionInfo
    return payloadInfo


def mkManifest(options, manifestInput):
    timestamp = manifestGet(manifestInput, 'resource.resource.manifest.timestamp')
    if not timestamp:
        timestamp = int(time.time())

    textFields = []
    description = manifestGet(manifestInput, 'resource.resource.manifest.description', 'description')
    if description:
        textFields.append({'type':'description', 'value':description})
    vendorDomain = manifestGet(manifestInput, 'vendorDomain')
    if vendorDomain:
        textFields.append({'type':'vendor', 'value':vendorDomain})
    modelName = manifestGet(manifestInput, 'modelName')
    if modelName:
        textFields.append({'type':'model', 'value':modelName})

    manifest = {
        'manifestVersion' : 'v2',
        'text'            : textFields,
        'nonce'           : uuid.uuid4().bytes,
        'digestAlgorithm' : {'algorithm':mkOIDtuple('2.16.840.1.101.3.4.2.1')},
        'timestamp'       : timestamp,
        'conditions'      : get_conditions(options, manifestInput),
        'directives'      : get_directives(options, manifestInput),
        'aliases'         : get_aliases(options, manifestInput),
        'dependencies'    : get_dependencies(options, manifestInput),
        'payloadInfo'     : get_payload_info(options, manifestInput)
    }
    if not manifest.get('payloadInfo') and not manifest['dependencies']:
        LOG.critical('No payload was specified and no dependencies were provided.')
        return None
    if manifest.get('payloadInfo') == 1:
        return None
    encoded_manifest = utils.encode(manifest, options, manifest_definition.Manifest())
    if not encoded_manifest:
        LOG.critical("Failed to encode manifest")
    return encoded_manifest

def get_ski(options, privateKey, manifestInput):
    certificates = []

    # Sign a test value
    test_value = uuid.uuid4()
    signature_value = privateKey.sign(
        test_value.bytes,
        ec.ECDSA(cryptoHashes.SHA256())
    )

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

    certificate = None
    ext = None

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
            LOG.critical("In ({file}): Only SHA256 certificates are supported by the update client at this time.".format(file=cPath))
            sys.exit(1)
        try:
            ext = certObj.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        except cryptography.x509.ExtensionNotFound:
            LOG.critical('Certificate does not contain SKI.')
            return None

        # Ensure that the certificate public key matches the private key.
        # First, get the public key:
        publicKey = certObj.public_key()
        # Verify the signature of the test value
        match = False
        try:
            publicKey.verify(signature_value, test_value.bytes, ec.ECDSA(cryptoHashes.SHA256()))
            match = True
        except cryptography.exceptions.InvalidSignature:
            pass

        if match:
            certificate = certObj
            break

    return ext.value.digest

def create_cms_signer_info(options, manifestInput, encoded_manifest):
    # Create the object representation of a CMS wrapper
    # There should always be a signing key on create.
    if not hasattr(options,'private_key') or not options.private_key:
        if 'private-key' in manifestInput:
            try:
                options.private_key = open(manifestInput['private-key'],'rb')
            except:
                LOG.critical('No private key specified and default key ({}) cannot be opened'.format(manifestInput['private-key']))
                sys.exit(1)
        else:
            LOG.critical('Resource is not signed and no signing key is provided.')
            sys.exit(1)

    ski = None
    manifest_hash = calculate_hash(options, encoded_manifest)

    # The attrValue specification in the ASN.1 file is "ANY". This poses some problems for encoding the maniffest.
    # The encoder will take any content provided to an "ANY" tag and include it verbatim. This means that the attrValues
    # must be encoded up-front.
    LOG.debug('Encoding id-data Object Identifier')
    id_data = utils.encode(mkOIDtuple('1.2.840.113549.1.7.1'), options, univ.ObjectIdentifier())
    LOG.debug('Encoding manifest hash OctetString')
    encoded_manifest_hash = utils.encode(manifest_hash, options, univ.OctetString())

    # Because the signed attributes must be signed, they are composed outside of the rest of the structure.
    signedAttrs = [
        {
            'attrType' : mkOIDtuple('1.2.840.113549.1.9.3'),
            'attrValues' : [
                id_data
            ]
        },
        {
            'attrType' : mkOIDtuple('1.2.840.113549.1.9.4'),
            'attrValues' : [
                encoded_manifest_hash
            ]
        }
    ]
    # Encode the signedAttrs. This encoding MUST be DER according to the CMS RFC (RFC5652). The signature is calculated
    # with the DER tag value of 0x31 (SET OF). However, the data included in the final manifest has a DER tag with value
    # 0xA0 (IMPLICIT [0]). This must also be known at signature verification time.
    LOG.debug('Encoding signed attributes')
    encoded_signedAttrs = utils.encode(signedAttrs, options, cms_signed_data_definition.SignedAttributes())
    # Make sure the first byte is 31 for signing
    if int(bytes(encoded_signedAttrs)[0]) != 0x31:
        LOG.critical('Signing failure: First byte of signed attributes was: {}, not 0x31'.format(bytes(encoded_signedAttrs[0])))
        return None

    private_key = None

    # load the private key
    private_key = keyserdes.load_pem_private_key(options.private_key.read(),
                                                 password=None,
                                                 backend=cryptoBackends.default_backend())

    # Sign the signed attributes
    # Note that this is the only use of encoded_signedAttrs. signedAttrs will be included in cms_signed_data for
    # encoding in the next step. This creates a slightly different structure to the one that is signed in this step:
    # instead of a 0x31 tag, signedAttrs will receive a 0xA0 tag. This is the behaviour specified in RFC5652.
    LOG.debug('Calculating signature value')
    signature_value = private_key.sign(
        encoded_signedAttrs,
        ec.ECDSA(cryptoHashes.SHA256())
    )

    # Fetch the signing key identifier
    LOG.debug('Finding Signing Key Identifier')
    ski = get_ski(options, private_key, manifestInput)
    if not ski:
        LOG.critical('Unable to find certificate matching {}'.format(options.private_key.name))
        return None
    signerInfo = { #SignerInfo
        'version' : 5,
        'sid' : {
            'subjectKeyIdentifier' : ski
        },
        'digestAlgorithm' : {'algorithm' : mkOIDtuple('2.16.840.1.101.3.4.2.1')},
        'signedAttrs' : signedAttrs,
        'signatureAlgorithm' : {'algorithm':mkOIDtuple('1.2.840.10045.4.3.2')},
        'signature' : signature_value
    }
    return signerInfo


def create_cms_wrapper(options, manifestInput, encoded_manifest):
    '''Creates a Cryptographic Message Syntax Signed Data container for the manifest.'''
    # This function uses pyASN1 to construct a CMS wrapper in order to sign the data.
    # pyASN1 requires that the input to an ANY field is fully encoded. This means that the CMS wrapper must be
    # constructed in pieces so that it can correctly encode each structure containing an "ANY" element.
    # These elements are:
    # * the value of each Signed Attribute
    # * the "content" field of ContentInfo

    signerInfo = create_cms_signer_info(options, manifestInput, encoded_manifest)
    if not signerInfo:
        return None

    # Construct the CMS signed data object
    cms_signedData = {
        'version' : 5,
        'digestAlgorithms' : [{
            'algorithm' : mkOIDtuple('2.16.840.1.101.3.4.2.1') #SHA-256
        }],
        'encapContentInfo' : {
            'eContentType' : mkOIDtuple('1.2.840.113549.1.7.1'),
            'eContent'     : encoded_manifest
        },
        'signerInfos' : [
            signerInfo
        ]
    }
    # # Encode the cms_signedData in advance, since ContentInfo's content field is an "ANY" type.
    # LOG.debug('Encoding Signed Data')
    # encoded_signedData = encode(cms_signedData, options, cms_signed_data_definition.SignedData())

    # ContentInfo
    cms_contentInfo = {
        'contentType' : '1.2.840.113549.1.7.2', # id-signedData
        'content' : { 'signedData' : cms_signedData }
    }
    # Encode the cms_contentInfo
    LOG.debug('Encoding Content Info')
    encoded_contentInfo = utils.encode(cms_contentInfo, options, cms_signed_data_definition.ContentInfo())
    return encoded_contentInfo

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
    LOG.warning('The v2 manifest is still under development and is subject to change.')
    LOG.warning('Please use v1 manifests for production devices')
    # Read options from manifest input file/
    # if (options.input_file.isatty()):
    #     LOG.info("Reading data from from active TTY... Terminate input with ^D")
    manifestInput = {}
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
        return 1

    # Parse input files and options. Generate hydrated and hierachial manifest JSON.
    encoded_manifest = mkManifest(options, manifestInput)
    if not encoded_manifest:
        return 1

    LOG.debug('Creating CMS wrapper')
    cms = create_cms_wrapper(options, manifestInput, encoded_manifest)
    if not cms:
        return 1
    LOG.debug('Manifest successfully encoded into desired format ({}). Size: {} bytes.'.format(options.encoding, len(cms)))

    # And we're done
    write_result(cms, options)
    return 0
