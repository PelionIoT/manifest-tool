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
from __future__ import print_function
import logging, sys, os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from six import text_type as text
import datetime
import binascii
from manifesttool import defaults
from manifesttool import utils

LOG = logging.getLogger(__name__)

def create(options):
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    options.key_output.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subjectList = []
    try:
        if options.country:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, text(options.country))]
        if options.state:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, text(options.state))]
        if options.locality:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, text(options.locality))]
        if options.organization:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, text(options.organization))]
        if options.common_name:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, text(options.common_name))]
        if len(subjectList) == 0:
            subjectList += [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, text('localhost'))]
        subject = issuer = x509.Name(subjectList)
    except ValueError as e:
        LOG.critical('Error creating certificate: {}'.format(e.message))
        fname = options.output_file.name
        options.output_file.close()
        os.remove(fname)
        return 1

    subjectKey = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    subjectKeyIdentifier = utils.sha_hash(subjectKey)[:160//8] # Use RFC7093, Method 1

    try:
        cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=options.valid_time)
            ).add_extension(
                x509.KeyUsage(
                     digital_signature = True,
                    content_commitment = False,
                      key_encipherment = False,
                     data_encipherment = False,
                         key_agreement = False,
                         key_cert_sign = False,
                              crl_sign = False,
                         encipher_only = False,
                         decipher_only = False),
                critical=False
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier(subjectKeyIdentifier),
                critical=False,
            # Sign our certificate with our private key
            ).sign(key, hashes.SHA256(), default_backend())
    except ValueError as e:
        LOG.critical('Error creating certificate: {}'.format(e.message))
        fname = options.output_file.name
        options.output_file.close()
        os.remove(fname)
        return 1
    # Write our certificate out to disk.
    options.output_file.write(cert.public_bytes(serialization.Encoding.DER))
    options.output_file.close()
    print('[\033[1;93mWARNING\033[1;0m]: Certificates generated with this tool are self-signed and for testing only',
            file=sys.stderr)
    if options.valid_time < 10 * 365.25:
        print('[\033[1;93mWARNING\033[1;0m]: This certificate is valid for {} days. For production,'
              'use certificates with at least 10 years validity.'.format(options.valid_time),
                file=sys.stderr)

    return 0

def add(options):
    if not hasattr(options, 'certificate'):
        LOG.critical('Cannot add certificate without certificate')
        return 1
    # Load the certificate
    cert = x509.load_der_x509_certificate(options.certificate.read(), default_backend())
    # Make sure the certificate uses SHA256.
    if not isinstance(cert.signature_hash_algorithm, hashes.SHA256):
        LOG.critical("In ({file}): Only SHA256 certificates are supported by the Mbed Cloud Update client at this time.".format(file=options.certificate.name))
        return 1
    if not isinstance(cert.public_key().curve, ec.SECP256R1):
        LOG.critical("In ({file}): Only secp256r1 (prime256v1) certificates are supported by the Mbed Cloud Update client at this time.".format(file=options.certificate.name))
        return 1

    fp = bytes(cert.fingerprint(hashes.SHA256()))
    newCertPath = os.path.join(defaults.certificatePath, binascii.b2a_hex(fp))
    with open(newCertPath, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
        LOG.info('Added certificate as: {}'.format(newCertPath))
    return 0

def read(options):
    pass

def main(options):
    return { "create": create,
      "add":    add,
    #   "read": parse
    }[options.cert_action](options)
