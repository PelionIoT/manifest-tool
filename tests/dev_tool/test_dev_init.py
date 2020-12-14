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

import yaml

from manifesttool.delta_tool.delta_tool import digest_file
from manifesttool.dev_tool import dev_tool, defaults
from tests import conftest


def test_cli(tmp_path):
    c_source = tmp_path / 'update_default_resources.c'
    cache_dir = tmp_path / defaults.BASE_PATH.as_posix()
    dev_cfg = cache_dir / defaults.DEV_CFG
    cert = cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT
    key = cache_dir / defaults.UPDATE_PRIVATE_KEY
    api_cfg = cache_dir / defaults.CLOUD_CFG

    dummy_api_key = '456321789541515'
    dummy_api_url = 'https://i.am.tired.of.writing.tests.com'

    cmd = [
        '--debug',
        'init'
    ]

    with conftest.working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd)

    assert not api_cfg.is_file()

    dev_cfg_digest = digest_file(dev_cfg)
    c_source_digest = digest_file(c_source)
    cert_digest = digest_file(cert)
    key_digest = digest_file(key)

    cmd = [
        'init',
        '--api-key', dummy_api_key,
        '--api-url', dummy_api_url
    ]

    with conftest.working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd + ['--api-url', 'https://some.url.pelion.com'])

    assert c_source_digest != digest_file(c_source)
    assert cert_digest != digest_file(cert)
    assert key_digest != digest_file(key)
    assert dev_cfg_digest != digest_file(dev_cfg)
    assert api_cfg.is_file()

    with conftest.working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd + ['--force'])

    assert c_source_digest != digest_file(c_source)
    assert cert_digest != digest_file(cert)
    assert key_digest != digest_file(key)
    assert dev_cfg_digest != digest_file(dev_cfg)

    with api_cfg.open('rb') as fh:
        api_cfg_data = yaml.safe_load(fh)
    assert dummy_api_key == api_cfg_data['api_key']
    assert dummy_api_url == api_cfg_data['host']
