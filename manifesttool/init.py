# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
from __future__ import print_function
from builtins import input, bytes, chr
import os, sys, json, logging, uuid
import re
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
        psk = ', '.join(['0x%x' % x for x in bytes(uuid.uuid4().bytes)])

        # Read the certificate
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
                psk = psk
        ))
        LOG.info('Wrote default resource values to {}'.format(defaults.updateResources))

def main(options):
    if hasattr(options, 'vendor_domain') and options.vendor_domain:
        if len(options.vendor_domain.split('.')) < 2:
            LOG.critical('"{0}" is not a valid domain name.'.format(options.vendor_domain))
            return 1
        options.vendor_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, options.vendor_domain))
    vendorId = uuid.UUID(options.vendor_id)

    if hasattr(options, 'model_name') and options.model_name:
        options.class_id = str(uuid.uuid5(vendorId, options.model_name))
    classId = uuid.UUID(options.class_id)

    cert_required = True
    certFile = None
    if options.certificate:
        cert_required = False
        certFile = options.certificate.name
    elif hasattr(options,'force') and options.force:
        cert_required = True
    else:
        try:
            options.certificate = open(defaults.certificate,'rb')
            options.private_key = open(defaults.certificateKey, 'rb')
            cert_required = False
            LOG.warning('{} and {} already exist, not overwriting.'.format(defaults.certificate, defaults.certificateKey))
        except:
            cert_required = True

    if cert_required:
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
            country = input('In which country is the subject located? ')
            state = input('In which state or province is the subject located? ')
            locality = input('In which city or region is the subject located? ')
            organization = input('What is the name of the subject organization? ')
            commonName = ''
            if hasattr(options, 'vendor_domain') and options.vendor_domain:
                commonName = input('What is the common name of the subject organization? [{}]'.format(options.vendor_domain)) or options.vendor_domain
            else:
                commonName = input('What is the common name of the subject organization? ')
            validity = input('How long (in days) should the certificate be valid? [{}]'.format(defaults.certificateDuration)) or defaults.certificateDuration

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
    # Write the settings

    settings = {
        'default-certificates' : [ {'file':options.certificate.name}],
        'signing-script' : options.signing_script,
        'private-key' : options.private_key.name,
        'classId' : str(classId),
        'vendorId' : str(vendorId),
        'vendorDomain' : options.vendor_domain,
        'modelName' : options.model_name
    }

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

    sys.exit(0)
