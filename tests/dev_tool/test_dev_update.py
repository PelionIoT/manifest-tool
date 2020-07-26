# ----------------------------------------------------------------------------
# Copyright 2019 ARM Limited or its affiliates
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
from mbed_cloud import UpdateAPI

from manifesttool.dev_tool import dev_tool
from tests import conftest


def mock_update_apis(mocker, status='autostopped'):
    mocker.patch.object(
        UpdateAPI, '__init__',
        lambda _self, conf: None
    )

    mocker.patch.object(
        UpdateAPI, 'add_firmware_image',
        return_value=mocker.MagicMock(url='http://some.nice.url')
    )

    mocker.patch.object(
        UpdateAPI, 'add_firmware_manifest',
        return_value=mocker.MagicMock(url='http://some.nice.url', id=100500)
    )

    mocker.patch.object(
        UpdateAPI, 'add_campaign',
        return_value=mocker.MagicMock(state='ready', device_filter=100500)
    )

    mocker.patch.object(UpdateAPI, 'start_campaign')

    mocker.patch.object(
        UpdateAPI, 'get_campaign',
        return_value=mocker.MagicMock(
            state=status,
            device_filter=100500)
    )

    mocker.patch.object(UpdateAPI, 'delete_campaign')
    mocker.patch.object(UpdateAPI, 'delete_firmware_manifest')
    mocker.patch.object(UpdateAPI, 'delete_firmware_image')


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_delta_happy_day(happy_day_data, action, mocker):
    mock_update_apis(mocker)

    assert 0 == _common(
        happy_day_data,
        action,
        happy_day_data['delta_file']
)


def _common(happy_day_data, action, payload_path):
    cmd = ['--debug'] + action + [
        '--cache-dir', happy_day_data['tmp_path'].as_posix(),
        '--payload-path', payload_path.as_posix(),
        '--vendor-data', happy_day_data['dev_cfg'].as_posix(),
        '--wait-for-completion',
        '--timeout', '1',
        '--device-id', '1234'
    ]
    if any(['v1' in x for x in action]):
        cmd.extend(['--fw-version', '100500'])
    else:
        cmd.extend(['--fw-version', '100.500.666'])

    with conftest.working_directory(happy_day_data['tmp_path']):
        return dev_tool.entry_point(cmd)


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_full_timeout(happy_day_data, action, mocker):
    mock_update_apis(mocker, 'scheduled')
    with pytest.raises(AssertionError):
        _common(
            happy_day_data,
            action,
            happy_day_data['fw_file']
        )

