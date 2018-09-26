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
import sys, argparse, os
from manifesttool import defaults, __version__

class MainArgumentParser(object):

    def __init__(self):
        self.parser = self._make_parser()

    def _make_parser(self):
        parser = argparse.ArgumentParser(description = 'Create or transform a manifest.'
        ' Use {} [command] -h for help on each command.'.format(sys.argv[0]))

        # Add all top-level commands
        parser.add_argument('-l', '--log-level', choices=['debug','info','warning','exception'], default='info')
        parser.add_argument('--version', action='version', version=__version__,
            help='display the version'
        )
        subparsers = parser.add_subparsers(dest="action")
        subparsers.required = True
        create_parser = subparsers.add_parser('create', help='Create a new manifest')
        parse_parser = subparsers.add_parser('parse', help='Parse an existing manifest')
        verify_parser = subparsers.add_parser('verify', help='Verify an existing manifest')
        cert_parser = subparsers.add_parser('cert', help='Create or examine a certificate')
        init_parser = subparsers.add_parser('init', help='Set default values for manifests',
            description='''Configures default values for manifests.

            The manifest init command requires a certificate. If one is not provided, init will guide the user through
            the process of creating a certificate. Currently, the only supported type of created certificate is
            self-signed, which should only be used for testing/development purposes.

            When using an existing certificate, the user may supply a script to use in performing signing operations.
            This script is to support the use of exsiting Hardware Security Modules, etc.''')
        sign_parser = subparsers.add_parser('sign', help='Sign an existing manifest',
            description='''Signs an existing manifest with one additional signature. The manifest must first be
            validated, so defaults for validation are extracted from .manifest_tool.json when values are not supplied
            as arguments to the tool''')
        update_parser = subparsers.add_parser('update', help='Work with the Mbed Cloud Update service')

        # Options for creating a new manifest
        self._addCreateArgs(create_parser)

        # Options for parsing an existing manifest
        parse_parser.add_argument('-j','--pretty-json', action='store_true')
        parse_parser.add_argument('-e','--encoding', choices=['der'], default='der',
            help='Decode created manifest using the provided encoding scheme')
        self._add_input_file_arg(parse_parser)
        self._add_output_file_arg(parse_parser)

        # Options for verifying an existing manifest
        self._addVerifyArgs(verify_parser)

        cert_subparsers = cert_parser.add_subparsers(dest="cert_action")
        cert_subparsers.required = True

        cert_create_parser = cert_subparsers.add_parser('create',
            help='Create a certificate.\nWARNING: Certificates generated with this tool are self-signed and for testing only.',
            description='Create a certificate.\nWARNING: Certificates generated with this tool are self-signed and for testing only.'
            )
        # cert_read_parser = cert_subparsers.add_parser('read', help='Create a certificate')

        cert_create_parser.add_argument('-C','--country', help='Country of the subject', required=False)
        cert_create_parser.add_argument('-S','--state', help='State or province of the subject', required=False)
        cert_create_parser.add_argument('-L','--locality', help='Locality (city or region) of the subject', required=False)
        cert_create_parser.add_argument('-O','--organization', help='Subject organization that will hold the certificate', required=False)
        cert_create_parser.add_argument('-U','--common-name', help='Common name for the subject organization', required=False)
        cert_create_parser.add_argument('-V','--valid-time', help='time for the certificate to be valid, in days, starting now',
                                        type=int, required=True)
        cert_create_parser.add_argument('-K','--key-output', help='file to store the private key generated for the new certificate',
                                        type=argparse.FileType('wb'), required=True)
        cert_add_parser = cert_subparsers.add_parser('add',
            help='Add a certificate to the manifest-tool\'s list of certificates for use in manifest-tool verify.',
            description='Adds a certificate to the {} directory.'.format(defaults.certificatePath))

        cert_add_parser.add_argument('-c', '--certificate',
            help='DER-encoded certificate to add to the certificate query directory ({})'.format(defaults.certificatePath),
            type=argparse.FileType('rb'), required=True)

        self._add_output_file_arg(cert_create_parser)

        init_parser.add_argument('-c','--certificate', help='Provide an existing certificate to init',
                                type=argparse.FileType('rb'), required=False)
        init_existing_cert_signing = init_parser.add_mutually_exclusive_group(required=False)
        init_existing_cert_signing.add_argument('-k','--private-key',
                                help='Provide a private key file for the certificate provided with -c. ' +
                                     'This allows the manifest tool to perform manifest signing internally.',
                                type=argparse.FileType('rb'))
        # init_existing_cert_signing.add_argument('-s','--signing-script',
        #                         help='Provide a script that should be used for signing. ' +
        #                              'This allows signing with existing infrastructure. ' +
        #                              'The arguments to the script are: {fingerprint of the certificate} '+
        #                              '{hash of the manifest}.',type=argparse.FileType('rb'))

        init_vendor_group = init_parser.add_mutually_exclusive_group(required=True)
        init_vendor_group.add_argument('-V', '--vendor-id', help='')
        init_vendor_group.add_argument('-d', '--vendor-domain', help='')

        init_class_group = init_parser.add_mutually_exclusive_group(required=True)
        init_class_group.add_argument('-C', '--class-id', help='')
        init_class_group.add_argument('-m', '--model-name', help='')

        init_parser.add_argument('-S', '--server-address', help='Address of the API server for updates')
        init_parser.add_argument('-a', '--api-key', help='API Key for the API server')
        init_parser.add_argument('-q', '--quiet', help='Do not prompt for certificate fields', action='store_true')
        init_parser.add_argument('-f', '--force', action='store_true',
            help='Overwrite existing update_default_resources.c')
        init_parser.add_argument('--psk', action='store_true', help='initialize this project as a PSK authentication project')

        self._addVerifyArgs(sign_parser, ['input-file'])
        sign_source_group = sign_parser.add_mutually_exclusive_group(required=True)
        sign_source_group.add_argument('-m', '--manifest', type=argparse.FileType('rb'), default=sys.stdin)
        # sign_source_group.add_argument('-u', '--url')

        sign_parser.add_argument('-k', '--private-key', metavar='KEY',
            help='Supply a private key, or a shared secret for signing a created manifest',
            type=argparse.FileType('rb'))
        sign_parser.add_argument('-c','--certificate',
            help='Provide an existing certificate to reference in the manifest signature. This must match the private key',
            type=argparse.FileType('rb'))

        update_sub_parsers = update_parser.add_subparsers(dest='update_action')

        prepare_parser = update_sub_parsers.add_parser('prepare', help='Prepare an update',
            description='''Prepares an update for Mbed Cloud. This uploads the specified payload, creates a manifest
            and uploads the manifest.''')

        self._addCreateArgs(prepare_parser, ['output-file'])
        prepare_parser.add_argument('-o', '--output-file', metavar='FILE',
            help='Specify the output file for the manifest. A temporary file is used by default.',
            type=argparse.FileType('wb'), default=None)

        prepare_parser.add_argument('-n', '--payload-name',
            help='The reference name for the payload in Mbed Cloud. If no name is specified, then one will be created '
                 'using the file name of the payload and the current timestamp.')
        prepare_parser.add_argument('-d', '--payload-description',
            help='The description of the payload for use in Mbed Cloud.')
        prepare_parser.add_argument('--manifest-name',
            help='The reference name for the manifest in Mbed Cloud. If no name is specified, then one will be created '
                 'using the file name of the manifest and the current timestamp.')
        prepare_parser.add_argument('--manifest-description',
            help='The description of the manifest for use in Mbed Cloud.')
        prepare_parser.add_argument('-a', '--api-key', help='API Key for the Mbed Cloud')

        update_device_parser = update_sub_parsers.add_parser('device',
            help='Update a single device using its LwM2M Device ID',
            description='''Update a single device using its LwM2M Device ID. Note that settings may be provided in the
                manifest tool configuration file ({}). The API key MUST be provided in the Mbed Cloud Client
                configuration file.'''.format(defaults.config))
        self._addCreateArgs(update_device_parser, ['output-file'])

        update_device_parser.add_argument('-o', '--output-file', metavar='FILE',
            help='Specify the output file for the manifest. A temporary file is used by default.',
            type=argparse.FileType('wb'), default=None)

        update_device_parser.add_argument('-n', '--payload-name',
            help='The reference name for the payload in Mbed Cloud. If no name is specified, then one will be created '
                 'using the file name of the payload and the current timestamp.')
        update_device_parser.add_argument('-d', '--payload-description',
            help='The description of the payload for use in Mbed Cloud.')
        update_device_parser.add_argument('--manifest-name',
            help='The reference name for the manifest in Mbed Cloud. If no name is specified, then one will be created '
                 'using the file name of the manifest and the current timestamp.')
        update_device_parser.add_argument('--manifest-description',
            help='The description of the manifest for use in Mbed Cloud.')
        update_device_parser.add_argument('-D', '--device-id', help='The device ID of the device to update', required=True)
        update_device_parser.add_argument('--no-cleanup', action='store_true',
            help='''Don't delete the campaign, manifest, and firmware image from Mbed Cloud when done''')
        update_device_parser.add_argument('-T', '--timeout', type=int, default=-1,
            help='''Set the time delay before the manifest tool aborts the campaign. Use -1 for indefinite (this is the default).''')
        update_device_parser.add_argument('-a', '--api-key', help='API Key for the Mbed Cloud')

        return parser

    def _add_input_file_arg(self, parser):
        parser.add_argument('-i', '--input-file', metavar='FILE',
            help='Specify the input file. stdin by default',
            type=argparse.FileType('rb'), default=sys.stdin)

    def _add_output_file_arg(self, parser):
        output_default = sys.stdout
        if sys.version_info.major == 3:
            output_default = sys.stdout.buffer
        parser.add_argument('-o', '--output-file', metavar='FILE',
            help='Specify the output file. stdout by default',
            type=argparse.FileType('wb'), default=output_default)
    def _addCreateArgs(self, parser, exclusions=[]):
        parser.add_argument('-v', '--manifest-version', choices=['1'], default='1')
        if not 'private-key' in exclusions:
            parser.add_argument('-k', '--private-key', metavar='KEY',
                help='Supply a private key, or a shared secret for signing a created manifest',
                type=argparse.FileType('rb'))
        # create_parser.add_argument('-e','--encrypt-payload', choices=['aes-psk'])
        # create_parser.add_argument('-s','--payload-secret', metavar='SECRET',
        #     help='Secret data used for encryption, e.g. a pre-shared key or a private key.\
        #           The exact contents is dictated by the encryption method used. The secret may\
        #           be base64 encoded or may be a filename.')
        if not 'mac' in exclusions:
            parser.add_argument('--mac',
                help='Use Pre-Shared-Key MAC authentication, with a master key supplied in --private-key. '
                'A filter ID or Device Unique ID is also required to specify which devices should have TAGs created. '
                'These can be supplied in --filter-id or --device-urn.\n'
                'The manifest tool will create a PSK for each device based on the master key and the concatenation of three LwM2M values: \n'
                '    /10255/0/3 (Vendor ID)\n'
                '    /10255/0/4 (Device Class ID)\n'
                '    Device URN (Endpoint Client Name)',
                action='store_true')
            parser.add_argument('--filter-id', help='specify which devices to use.')
            parser.add_argument('--device-urn', action='append',
                help='Specify devices to target with the update by their URNs (Endpoint Client Name). '
                'The manifest tool will derive a PSK for the specified device based on the master key and the concatenation of: \n'
                '    Vendor ID\n'
                '    Device Class ID\n'
                '    Device URN\n'
                '--device-urn can be used multiple times to specify multiple devices.')
            parser.add_argument('--psk-table', help='Specify the file to use to store the PSK table. '
                'This file is used with the --mac argument in order to specify the output file for the pre-shared keys. '
                'The table is composed of three columns: device URN, WrappedManifestDigest, and WrappedPayloadKey.',
                type=argparse.FileType('wb'))
            parser.add_argument('--psk-table-encoding', help='', choices=['protobuf', 'text'], default='text')
        if not 'payload-key' in exclusions:
            parser.add_argument('--payload-key', help='supply the payload encryption key. This is the key that is used encrypt the payload. '
                'The payload key is encrypted for each device using a shared secret.')
        if not 'payload' in exclusions:
            parser.add_argument('-p', '--payload',
                help='Supply a local copy of the payload file.'
                     'This option overrides any payload file supplied in a `-i` argument.', metavar='FILE',
                type=argparse.FileType('rb'), required = True)
        if not 'uri' in exclusions:
            parser.add_argument('-u', '--uri',
                help='Supply the URI of the payload. '
                     'When a payload is uploaded to cloud storage, this is the URL of the payload. '
                     'This option overrides any URI supplied in a `-i` argument.')
            parser.add_argument('--url', help='Synonym for `--uri`', dest='uri')
        if not 'encoding' in exclusions:
            parser.add_argument('-c','--encoding', choices=['der'], default='der',
                help='Encode created manifest using the provided encoding scheme')
        if not 'hex' in exclusions:
            parser.add_argument('-x', '--hex', action='store_true',
                help='Output data in hex octets')
        if not 'c-file' in exclusions:
            parser.add_argument('-C', '--c-file', action='store_true',
                help='Output data as a C file')
        if not 'input-file' in exclusions:
            self._add_input_file_arg(parser)
        if not 'output-file' in exclusions:
            self._add_output_file_arg(parser)

    def _addVerifyArgs(self, verify_parser, exclusions=[]):
        if not 'pretty-json' in exclusions:
            verify_parser.add_argument('-j','--pretty-json', action='store_true')
        if not 'encoding' in exclusions:
            verify_parser.add_argument('-e','--encoding', choices=['der'], default='der',
                help='Decode created manifest using the provided encoding scheme')
        if not 'certificate-directory' in exclusions:
            verify_parser.add_argument('-d','--certificate-directory', default=defaults.certificatePath,
                help='A directory that contains the certificates necessary to validate a manifest. These should be named with their fingerprint.')
        if not 'vendor-id' in exclusions:
            verify_parser.add_argument('-V','--vendor-id', dest='vendorId', metavar='VENDORID',
                help='Set the vendor UUID that verify should expect.' )
        if not 'class-id' in exclusions:
            verify_parser.add_argument('-C','--class-id', dest='classId', metavar='CLASSID',
                help='Set the class UUID that verify should expect.' )
        if not 'input-file' in exclusions:
            self._add_input_file_arg(verify_parser)
        if not 'output-file' in exclusions:
            self._add_output_file_arg(verify_parser)

    def _verify_arguments(self):
        """Custom logic to ensure valid arguments are passed in"""
        # if self.options.action == "create":
        #     if self.options.encrypt_payload and not self.options.payload_secret:
        #         self.parser.error('A secret must be supplied with --payload-secret option when the --encrypt-payload option is in use.')
        pass

    def parse_args(self, args=None):
        self.options = self.parser.parse_args(args)
        self._verify_arguments()
        return self
