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
import uuid

import yaml

from manifesttool.dev_tool.actions.init import generate_credentials
from manifesttool.dev_tool.actions.init import generate_developer_config


def test_generate_developer_config_happy_day(tmp_path):
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    generate_credentials(
        key_file=key_file,
        cert_file=certificate_file,
        cred_valid_time=8
    )
    config = tmp_path / 'my_cfg.yaml'
    class_id = uuid.uuid4()
    vendor_id = uuid.uuid4()
    generate_developer_config(
        key_file=key_file,
        cert_file=certificate_file,
        config=config,
        class_id=class_id,
        vendor_id=vendor_id
    )
    with config.open('rb') as fh:
        raw_cfg = yaml.safe_load(fh)

    assert 'key_file' in raw_cfg
    assert 'vendor-id' in raw_cfg
    assert len(raw_cfg['vendor-id']) == 32
    assert 'class-id' in raw_cfg
    assert len(raw_cfg['class-id']) == 32
