# ----------------------------------------------------------------------------
# Copyright 2019-2020 Pelion
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

import argparse
import binascii
import collections
import logging

import yaml
from pyasn1.error import PyAsn1Error

from manifesttool.mtool import ecdsa_helper
from manifesttool.mtool.asn1 import ManifestVersion


def bytes_representer(dumper: yaml.Dumper, obj):
    try:
        return dumper.represent_str(obj.decode('utf-8'))
    except UnicodeError:
        return dumper.represent_str(binascii.hexlify(obj).decode('utf-8'))


def ordered_dict_representer(dumper, data):
    return dumper.represent_dict(data.items())


yaml.Dumper.add_representer(collections.OrderedDict, ordered_dict_representer)
yaml.Dumper.add_representer(bytes, bytes_representer)

class ParseAction:

    logger = logging.getLogger('manifest-tool-parse')

    @staticmethod
    def register_parser_args(parser):
        required = parser.add_argument_group('required arguments')
        optional = parser.add_argument_group('optional arguments')

        required.add_argument(
            'manifest',
            help='Path to the manifest file.',
            type=argparse.FileType('rb')
        )

        key_or_cert_group = optional.add_mutually_exclusive_group()
        key_or_cert_group.add_argument(
            '-c', '--certificate',
            help='Path to a certificate file to validate '
                 'the manifest signature.',
            type=argparse.FileType('rb')
        )
        key_or_cert_group.add_argument(
            '-p', '--public-key',
            help='Path to a public key file, '
                 'containing a key in uncompressed point format, '
                 'to validate the manifest signature.',
            type=argparse.FileType('rb')
        )
        key_or_cert_group.add_argument(
            '-k', '--private-key',
            help='Path to a private key PEM file '
                 'to validate the manifest signature.',
            type=argparse.FileType('rb')
        )

        optional.add_argument(
            '-h',
            '--help',
            action='help',
            help='Show this help message and exit.'
        )

    # pylint: disable=too-many-branches
    @classmethod
    def do_parse(
            cls,
            manifest_data: bytes,
            certificate_data: bytes,
            public_key_data: bytes,
            private_key_data: bytes
    ):
        dom = None

        public_key = None
        if private_key_data:
            public_key = ecdsa_helper.public_key_from_private(private_key_data)
        elif certificate_data:
            try:
                public_key = ecdsa_helper.public_key_from_certificate(
                    certificate_data)
            except ValueError as ex:
                raise AssertionError('Malformed certificate') from ex
        elif public_key_data:
            public_key = ecdsa_helper.public_key_from_bytes(public_key_data)

        for codec_class in ManifestVersion.list_codecs():
            try:
                dom = codec_class.decode(
                    manifest_data, public_key)
                break
            except PyAsn1Error:
                continue
        if not dom:
            raise AssertionError('Malformed manifest')

        logging.info(
            '\n----- Manifest dump start -----\n'
            '%s----- Manifest dump end -----',
            yaml.dump(dom, default_flow_style=False)

        )

    @classmethod
    def entry_point(cls, args):
        cert_data = args.certificate.read() if args.certificate else None
        public_key = args.public_key.read() if args.public_key else None
        private_key = args.private_key.read() if args.private_key else None
        manifest_data = args.manifest.read()

        cls.do_parse(
            manifest_data=manifest_data,
            certificate_data=cert_data,
            public_key_data=public_key,
            private_key_data=private_key
        )
