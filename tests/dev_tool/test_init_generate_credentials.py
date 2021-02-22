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
import pytest

from manifesttool.delta_tool.delta_tool import digest_file
from manifesttool.dev_tool.actions.init import generate_credentials


def test_happy_day(tmp_path):
    generate_credentials(
        key_file=tmp_path / 'dev.key.pem',
        cert_file=tmp_path / 'dev.cert.der',
        cred_valid_time=8
    )


def test_overwriting_keys(tmp_path):
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    generate_credentials(
        key_file=key_file,
        cert_file=certificate_file,
        cred_valid_time=8
    )
    key_digest = digest_file(key_file)
    cert_digest = digest_file(certificate_file)
    generate_credentials(
        key_file=key_file,
        cert_file=certificate_file,
        cred_valid_time=8
    )
    assert key_digest != digest_file(key_file)
    assert cert_digest != digest_file(certificate_file)
