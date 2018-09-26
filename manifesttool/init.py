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
from __future__ import print_function, division
from builtins import input, bytes, chr
import os, sys, json, logging, uuid, re
import binascii
from manifesttool import defaults, cert, utils, templates
from manifesttool.argparser import MainArgumentParser
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

LOG = logging.getLogger(__name__)

def writeUpdateDefaults(options):
    if os.path.isfile(defaults.updateResources) and not (hasattr(options, 'force') and options.force):
        LOG.warning('{} already exists, not overwriting. Use --force to write anyway.'.format(defaults.updateResources))
        return
    with open(defaults.updateResources, 'w') as defaultResources:
        # Format the device UUIDs
        vendorId = ', '.join(['0x%x' % x for x in bytes(uuid.UUID(options.vendor_id).bytes)])
        classId = ', '.join(['0x%x' % x for x in bytes(uuid.UUID(options.class_id).bytes)])

        certFp = ''
        cert = ''
        str_ski = ''
        # Read the certificate
        if not hasattr(options, 'psk') or not options.psk:
            options.certificate.seek(0)
            cstr = options.certificate.read()
            try:
                # Load the certificate.
                certObj = x509.load_der_x509_certificate(
                    cstr,
                    default_backend()
                )
            except ValueError as e:
                raise ValueError('Error loading {}: {}'.format(options.certificate.name, e.message))
            # Calculate the certificate fingerprint
            c_hash = certObj.fingerprint(hashes.SHA256())
            # Format the certificate fingerprint
            certFp = ', '.join(['0x%x' % x for x in bytes(c_hash[:16])]) + ',\n    ' + ', '.join(['0x%x' % x for x in bytes(c_hash[16:])])

            # Calculate the subjectKeyIdentifier
            c_ski = certObj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
            str_ski = ', '.join(['0x%x' % x for x in bytes(c_ski[:16])]) + ',\n    ' + ', '.join(['0x%x' % x for x in bytes(c_ski[16:])])

            # Format the certificate
            CByteArray = [ '0x%x'% x for x in bytes(cstr)]
            CLineList = [ ', '.join(CByteArray[i:i+16]) for i in range(0,len(CByteArray),16)]
            cert = ',\n    '.join(CLineList)

        defaultResources.write(templates.UpdateDefaultResources.format(
                vendorId = vendorId,
                classId = classId,
                certFp = certFp,
                ski = str_ski,
                cert = cert,
                psk = ', '.join(['0x%x'%x for x in bytes(options.psk)]),
                pskId = ', '.join(['0x%x'%x for x in bytes(options.psk_id)])
        ))
        LOG.info('Wrote default resource values to {}'.format(defaults.updateResources))

def mkCert(options):
        cmd = ['cert', 'create', '-o', defaults.certificate, '-K', defaults.certificateKey]

        country = ''
        state = ''
        locality = ''
        organization = ''
        commonName = ''
        if hasattr(options, 'vendor_domain') and options.vendor_domain:
            commonName = options.vendor_domain
        validity = defaults.certificateDuration

        if not options.quiet:
            print('A certificate has not been provided to init, and no certificate is provided in {cert}'.format(
                cert=defaults.certificate))
            print('Init will now guide you through the creation of a certificate.')
            print()
            print('This process will create a self-signed certificate, which is not suitable for production use.')
            print()
            print('In the terminology used by certificates, the "subject" means the holder of the private key that matches a certificate.')
            country = input('In which country is the subject located? ').strip()
            state = input('In which state or province is the subject located? ').strip()
            locality = input('In which city or region is the subject located? ').strip()
            organization = input('What is the name of the subject organization? ').strip()
            commonName = ''
            if hasattr(options, 'vendor_domain') and options.vendor_domain:
                commonName = input('What is the common name of the subject organization? [{}]'.format(options.vendor_domain)).strip() or options.vendor_domain
            else:
                commonName = input('What is the common name of the subject organization? ')
            validity = input('How long (in days) should the certificate be valid? [{}]'.format(defaults.certificateDuration)).strip() or defaults.certificateDuration

        try:
            os.makedirs(defaults.certificatePath)
        except os.error:
            # It is okay if the directory already exists. If something else went wrong, we'll find out when the
            # create occurs
            pass

        cmd = ['cert', 'create', '-o', defaults.certificate, '-K', defaults.certificateKey,
            '-V', str(validity)]
        if country:
            cmd += ['-C', country]
        if state:
            cmd += ['-S', state]
        if locality:
            cmd += ['-L', locality]
        if organization:
            cmd += ['-O', organization]
        if commonName:
            cmd += ['-U', commonName]
        cert_opts = MainArgumentParser().parse_args(cmd).options
        rc = cert.main(cert_opts)
        if rc:
            sys.exit(1)
        options.certificate = open(defaults.certificate, 'rb')
        LOG.info('Certificate written to {}'.format(defaults.certificate))
        options.private_key = open(defaults.certificateKey, 'rb')
        LOG.info('Private key written to {}'.format(defaults.certificateKey))

def checkURN(deviceURN):
    URNsplit = deviceURN.split(':')
    if len(URNsplit) < 3 or URNsplit[0] != 'urn':
        raise ValueError('PSK Identity does not appear to be a valid URN: {!r}'.format(deviceURN))
    if URNsplit[1] not in ['dev', 'uuid', 'imei', 'esn', 'meid', 'imei-msisdn', 'imei-imsi']:
        raise ValueError('{!r} is not a recommended URN class for PSK identities')
    if URNsplit[1] == 'dev' and URNsplit[2] != 'ops':
        raise ValueError('ops-type URNs are recommended dev-class URNs for PSK identities')

def findDevCertFiles(textPattern, directorySearchPaths, searchExtension):
    IdentityFiles = []
    AllSourceFiles = []
    for path in directorySearchPaths:
        if os.path.isdir(path):
            for file in os.listdir(path):
                if file.endswith(searchExtension):
                    AllSourceFiles.append(os.path.join(path,file))
    for file in AllSourceFiles:
        with open(file, 'rt') as fd:
            for line in fd:
                if textPattern in line:
                    IdentityFiles.append(file)
    if len(IdentityFiles) > 1:
        raise ValueError('Multiple Endpoint Name definitions found!')
        sys.exit(1)
    else:
        if len(IdentityFiles) == 1:
            return IdentityFiles[0]
        else:
            return ''


def main(options):

    settings = {}
    # Check if a settings file exists
    if os.path.isfile(defaults.config):
        # load default settings
        with open(defaults.config,'r') as f:
            settings = json.load(f)
    # Populate a default list of PSKIdentities
    PSKIdentities = settings.get('deviceURNs', [])
    print (PSKIdentities)

    if hasattr(options, 'vendor_domain') and options.vendor_domain:
        domainParts = options.vendor_domain.split('.')
        minPart = min(domainParts)
        if len(domainParts) < 2 or len(minPart) < 1:
            LOG.critical('"{0}" is not a valid domain name.'.format(options.vendor_domain))
            return 1
        options.vendor_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, options.vendor_domain))
    vendorId = uuid.UUID(options.vendor_id)

    if hasattr(options, 'model_name') and options.model_name:
        options.class_id = str(uuid.uuid5(vendorId, options.model_name))
    classId = uuid.UUID(options.class_id)

    if hasattr(options, 'psk') and options.psk:
        # Attempt to read the device endpoint name out of mbed_cloud_dev_credentials.c
        deviceURN = None
        try:
            dev_credential_dirs = ['.','source']
            dev_cred_file_name = findDevCertFiles('MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME', dev_credential_dirs, '.c')
            with open(dev_cred_file_name, 'rt') as fd:
                URNLine = None
                for line in fd:
                    if 'MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME' in line:
                        URNLine = line
                        break
                if URNLine:
                    m = re.search('const\s+char\s+MBED_CLOUD_DEV_BOOTSTRAP_ENDPOINT_NAME\\[\\]\s*=\s*"([^"]*)";', URNLine)
                    if m:
                        deviceURN = m.group(1)
        except IOError:
            # Handle missing file
            pass

        if len(PSKIdentities) == 0:
            # endpoint name must be set in the credentials file if there are no endpoints in the configuration already
            if not deviceURN:
                LOG.critical('An endpoint name must be populated in mbed_cloud_dev_credentials.c')
                return 1
            if deviceURN == '0':
                LOG.critical('An endpoint name in mbed_cloud_dev_credentials.c must be initialized (not \'0\') and must be different for each device.')
                return 1
            else:
                if deviceURN in PSKIdentities:
                    LOG.warning('Device URN %r already exists in .manifest-tool.json. Is it unique?', deviceURN)
                try:
                    checkURN(deviceURN)
                except ValueError as e:
                    LOG.warning('%s', e.message)

                # Append the device URN extracted from the credentials file to the current list
                PSKIdentities.append(deviceURN)

        # Install the device URN extracted from the credentials file into the options object for
        # use in generating template files
        options.device_urn = deviceURN
        masterKey = None
        masterKeyRequired = not hasattr(options, 'master_key') or not options.master_key
        if masterKeyRequired:
            try:
                # Open and store to master_key since this matches what argparse is doing
                options.master_key = open(defaults.pskMasterKey, 'rb')
                masterKeyRequired = False
                if options.force:
                    LOG.warning("Using existing master key in %r. Not generating a new master key.",
                        defaults.pskMasterKey)
            except:
                masterKeyRequired = True

        if masterKeyRequired:
            LOG.info('Generating a new 256-bit master key')
            masterKey = os.urandom(256//8)
            masterKeyName = defaults.pskMasterKey
            try:
                os.makedirs(defaults.certificatePath)
            except os.error:
                # It is okay if the directory already exists. If something else went wrong, we'll find out when the
                # create occurs
                pass
            # Open and store to master_key since this matches what argparse is doing
            options.master_key = open(masterKeyName,'wb')
            LOG.info('Storing master key to %r', options.master_key.name)
            options.master_key.write(masterKey)
            options.master_key.flush()
            options.master_key.seek(0)
        else:
            LOG.info('Reading master key out of {}'.format(options.master_key.name))
            masterKey = options.master_key.read()

        # Generate the device PSK
        shaMaster = hashes.Hash(hashes.SHA256(), default_backend())
        shaMaster.update(masterKey)
        options.psk_id = shaMaster.finalize()
        psk_hkdf = utils.getDevicePSK_HKDF('none-psk-aes-128-ccm-sha256', masterKey, vendorId.bytes, classId.bytes, b'Authentication')
        options.psk = psk_hkdf.derive(bytes(options.device_urn, 'utf-8'))

    else:
        cert_required = True
        options.psk_id = bytes('', 'utf-8')
        options.psk = bytes('', 'utf-8')
        options.device_urn = ''
        if options.certificate:
            cert_required = False
        elif hasattr(options,'force') and options.force:
            cert_required = True
        else:
            try:
                options.certificate = open(defaults.certificate,'rb')
                options.private_key = open(defaults.certificateKey, 'rb')
                cert_required = False
            except:
                cert_required = True

        if cert_required:
            mkCert(options)
    # Write the settings

    settings = {
        'classId' : str(classId),
        'vendorId' : str(vendorId),
        'vendorDomain' : options.vendor_domain,
        'modelName' : options.model_name,
        'deviceURNs' : list(set(PSKIdentities))
    }

    if hasattr(options, 'psk') and options.psk:
        settings['psk-master-key'] = options.master_key.name
    else:
        settings['private-key'] = options.private_key.name
        settings['default-certificates'] = [ {'file':options.certificate.name}]

    with open(defaults.config, 'w') as f:
        f.write(json.dumps(settings, sort_keys=True, indent=4))
        LOG.info('Default settings written to {}'.format(defaults.config))

    try:
        writeUpdateDefaults(options)
    except ValueError as e:
        LOG.critical('Error setting defaults: {}'.format(e.message))
        return 1

    cloud_settings = {}
    if hasattr(options, 'server_address') and options.server_address:
        cloud_settings['host'] = options.server_address
    if hasattr(options, 'api_key') and options.api_key:
        cloud_settings['api_key'] = options.api_key

    if cloud_settings:
        with open(defaults.cloud_config, 'w') as f:
            f.write(json.dumps(cloud_settings, sort_keys=True, indent=4))
            LOG.info('Cloud settings written to {}'.format(defaults.cloud_config))

    return 0
