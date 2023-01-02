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
from manifesttool.package_tool.actions.create import CreateAction as PackageCreateAction
from tests.conftest import working_directory


@pytest.mark.parametrize(
    'action',
    [
        ['create'],
        ['create', '-r', '1'],
        ['create', '--sign-image'],
        ['create', '--combined-image'],
        ['create-v1'],
        ['create-v1', '--fw-migrate-ver', '1.2.3'],

    ]
)
def test_cli_developer(happy_day_data, action):

    dev_cfg = happy_day_data['tmp_path'] / defaults.DEV_CFG
    payload_path = happy_day_data['fw_file'].as_posix()
    if '--combined-image' in action:
        generate_package(happy_day_data)
        payload_path = happy_day_data['package_data']['out_file_name']
    elif '-r' in action:
        payload_path = happy_day_data['delta_file'].as_posix()
    class_id = uuid.uuid4()
    vendor_id = uuid.uuid4()
    generate_developer_config(
        key_file=happy_day_data['key_file'],
        cert_file=happy_day_data['certificate_file'],
        config=dev_cfg,
        class_id = class_id,
        vendor_id = vendor_id
    )

    output_manifest = happy_day_data['tmp_path'] / 'manifest.bin'
    cmd = ['--debug'] + action + [
        '--priority', '100500',
        '--output', output_manifest.as_posix(),
        '--cache-dir', happy_day_data['tmp_path'].as_posix(),
        '--payload-url', 'https://izumanetworks.com/foo.bin?id=67567565576857',
        '--payload-path', payload_path,
        '--vendor-data', dev_cfg.as_posix(),
    ]

    if '-fw-version' not in action and \
        '--fw-migrate-ver' not in action:
        if action[0] == 'create-v1':
            cmd.extend(['--fw-version', '100500'])
        else:
            cmd.extend(['--fw-version', '100.500.666'])

    with working_directory(happy_day_data['tmp_path']):
        assert 0 == dev_tool.entry_point(cmd)

def generate_package(happy_day_data):
    # Create package
    PackageCreateAction.do_create(happy_day_data['package_data']['input_cfg'], \
        happy_day_data['package_data']['out_file_name'], 'tar')
