# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
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
import logging
import os
import sys

import pytest
from _pytest.tmpdir import TempPathFactory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from manifesttool.dev_tool.actions.init import generate_credentials
from manifesttool.mtool import mtool
from manifesttool.mtool.actions.create import CreateAction
from manifesttool.mtool.actions.parse import ParseAction
from manifesttool.mtool.asn1 import ManifestVersion

logging.basicConfig(
    stream=sys.stdout,
    format='%(asctime)s %(levelname)s %(message)s',
    level=logging.DEBUG
)

@pytest.fixture(params=ManifestVersion.list_codecs())
def happy_day_data(
        tmp_path_factory: TempPathFactory,
        request
):
    tmp_path = tmp_path_factory.mktemp("data")
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    manifest_version = request.param  # Type[ManifestAsnCodecBase]
    generate_credentials(
        key_file=key_file,
        certificate_file=certificate_file,
        cred_valid_time=8
    )
    fw_file = tmp_path / 'fw.bin'
    fw_file.write_bytes(os.urandom(512))

    input_cfg = {
        "manifest-version": manifest_version.get_name(),
        "vendor": {
            "domain": "pelion.com",
            "custom-data-path": fw_file.as_posix()

        },
        "device": {
            "model-name": "my-device"
        },
        "priority": 15,
        "payload": {
            "url": "https://my.server.com/some.file?new=1",
            "file-path": fw_file.as_posix(),
            "format": "raw-binary"
        }
    }

    fw_version = '100.500.0'
    if 'v1' == manifest_version.get_name():
        fw_version = 0
    else:
        input_cfg['sign-image'] = True

    manifest_data = CreateAction.do_create(
        pem_key_data=key_file.read_bytes(),
        input_cfg=input_cfg,
        fw_version=fw_version,
        update_certificate=certificate_file,
        asn1_codec_class=manifest_version
    )
    manifest_file = tmp_path / 'fota_manifest.bin'
    manifest_file.write_bytes(manifest_data)

    private_key = serialization.load_pem_private_key(
        key_file.read_bytes(),
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    public_key_file = tmp_path / 'pub_key.bin'
    public_key_file.write_bytes(public_key_bytes)

    return {
        'manifest_file': manifest_file,
        'certificate_file': certificate_file,
        'pub_key_file': public_key_file,
        'priv_key_file': key_file,
        'manifest_version': manifest_version.get_name(),
    }


def test_parse_happy_day(happy_day_data):
    ParseAction.do_parse(
        certificate_data=None,
        manifest_data=happy_day_data['manifest_file'].read_bytes(),
        public_key_data=None,
        private_key_data=None
    )


def test_parse_and_verify_happy_day(happy_day_data):
    ParseAction.do_parse(
        certificate_data=happy_day_data['certificate_file'].read_bytes(),
        manifest_data=happy_day_data['manifest_file'].read_bytes(),
        public_key_data=None,
        private_key_data=None
    )

def test_cli_parse_and_verify_happy_day_cert(happy_day_data):

    cmd = [
        '--debug',
        'parse',
        happy_day_data['manifest_file'].as_posix(),
        '--certificate', happy_day_data['certificate_file'].as_posix(),
    ]

    assert 0 == mtool.entry_point(cmd)

def test_cli_parse_and_verify_happy_day_pubkey(happy_day_data):
    cmd = [
        '--debug',
        'parse',
        '--public-key', happy_day_data['pub_key_file'].as_posix(),
        happy_day_data['manifest_file'].as_posix()
    ]

    assert 0 == mtool.entry_point(cmd)


def test_cli_parse_and_verify_happy_day_privkey(happy_day_data):
    cmd = [
        '--debug',
        'parse',
        happy_day_data['manifest_file'].as_posix(),
        '--private-key', happy_day_data['priv_key_file'].as_posix()
    ]

    assert 0 == mtool.entry_point(cmd)

@pytest.mark.parametrize('manifest_version', ManifestVersion.list_codecs())
def test_parse_malformed(manifest_version):
    certificate_data = os.urandom(512)
    manifest_data = os.urandom(512)
    with pytest.raises(AssertionError) as e:
        ParseAction.do_parse(
            certificate_data=certificate_data,
            manifest_data=manifest_data,
            public_key_data=None,
            private_key_data=None
        )
        assert "Malformed manifest" in str(e)


def test_verify_malformed_certificate(happy_day_data):
    certificate_data = os.urandom(512)
    with pytest.raises(AssertionError) as e:
        ParseAction.do_parse(
            certificate_data=certificate_data,
            manifest_data=happy_day_data['certificate_file'].read_bytes(),
            public_key_data=None,
            private_key_data=None
        )
        assert 'Malformed certificate' in str(e)


def test_parse_and_verify_bad_signature(tmp_path, happy_day_data):
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    generate_credentials(
        key_file=key_file,
        certificate_file=certificate_file,
        cred_valid_time=8
    )
    with pytest.raises(AssertionError) as e:
        ParseAction.do_parse(
            certificate_data=certificate_file.read_bytes(),
            manifest_data=happy_day_data['manifest_file'].read_bytes(),
            public_key_data=None,
            private_key_data=None
        )
        assert 'Signature verification failed' in str(e)
