# ----------------------------------------------------------------------------
# Copyright 2020 Pelion
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
import sys

import pytest
from _pytest.tmpdir import TempPathFactory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from manifesttool.dev_tool.actions.init import generate_credentials
from manifesttool.mtool import mtool
from manifesttool.mtool.actions.public_key import PublicKeyAction

logging.basicConfig(
    stream=sys.stdout,
    format='%(asctime)s %(levelname)s %(message)s',
    level=logging.DEBUG
)

@pytest.fixture()
def text_fixture(
        tmp_path_factory: TempPathFactory
):
    tmp_path = tmp_path_factory.mktemp("data")
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    generate_credentials(
        key_file=key_file,
        certificate_file=certificate_file,
        cred_valid_time=8
    )

    return {
        'tmp_path': tmp_path,
        'key_file': key_file
    }


def test_parse_happy_day(text_fixture):
    PublicKeyAction.get_key(
        text_fixture['key_file'].read_bytes()
    )

def test_parse_happy_day_cli(text_fixture):
    output_file = text_fixture['tmp_path'] / 'out.bin'
    cmd = [
        '--debug',
        'public-key',
        text_fixture['key_file'].as_posix(),
        '--out', output_file.as_posix()
    ]

    assert 0 == mtool.entry_point(cmd)

    assert output_file.is_file()
    assert output_file.stat().st_size == 65  # 0x04 + 32B + 32B

    private_key = serialization.load_pem_private_key(
        text_fixture['key_file'].read_bytes(),
        password=None,
        backend=default_backend()
    )

    message = b'my super duper secret data to be signed'

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve=ec.SECP256R1(),
        data=output_file.read_bytes()
    )

    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
