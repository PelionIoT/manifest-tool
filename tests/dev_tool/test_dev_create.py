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

import pytest

from manifesttool.dev_tool import defaults
from manifesttool.dev_tool import dev_tool
from manifesttool.dev_tool.actions.init import generate_developer_config
from tests import conftest


@pytest.mark.parametrize(
    'action',
    [
        ['create'],
        ['create', '--sign-image'],
        ['create-v1']
    ]
)
def test_cli_developer(happy_day_data, action):

    dev_cfg = happy_day_data['tmp_path'] / defaults.DEV_CFG
    class_id = uuid.uuid4()
    vendor_id = uuid.uuid4()
    generate_developer_config(
        key_file=happy_day_data['key_file'],
        certificate_file=happy_day_data['certificate_file'],
        config=dev_cfg,
        class_id = class_id,
        vendor_id = vendor_id
    )

    output_manifest = happy_day_data['tmp_path'] / 'manifest.bin'
    cmd = ['--debug'] + action + [
        '--priority', '100500',
        '--output', output_manifest.as_posix(),
        '--cache-dir', happy_day_data['tmp_path'].as_posix(),
        '--payload-url', 'https://pelion.com/foo.bin?id=67567565576857',
        '--payload-path', happy_day_data['delta_file'].as_posix(),
        '--vendor-data', dev_cfg.as_posix(),
    ]

    if not any(['v1' in x for x in action]):
        cmd.extend(['--fw-version', '100.500.0'])

    with conftest.working_directory(happy_day_data['tmp_path']):
        assert 0 == dev_tool.entry_point(cmd)