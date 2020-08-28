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
import urllib

import pytest

from manifesttool.dev_tool import dev_tool
from manifesttool.dev_tool.pelion.pelion import *
from tests import conftest

def api_url(api, **kwargs):
    if kwargs:
        return urllib.parse.urljoin(
            'https://api.us-east-1.mbedcloud.com', api.format(**kwargs))
    return urllib.parse.urljoin('https://api.us-east-1.mbedcloud.com', api)

def mock_update_apis(
        requests_mock,
        state='autostopped',
        phase='active',
        deployment_state='deployed',
        http_status_code=200
):
    job_id = 123
    firmware_image_id = 654
    # -------------------------------------------------------------------------
    #                        FW image upload URL mocks
    # -------------------------------------------------------------------------

    # FW upload job - create
    requests_mock.post(
        api_url(FW_UPLOAD_JOBS),
        json={'id': job_id},
        status_code=http_status_code
    )

    # FW upload job - upload chunk
    requests_mock.post(
        api_url(FW_UPLOAD_JOB_CHUNK, id=job_id),
        status_code=http_status_code
    )

    # FW upload job - delete
    requests_mock.delete(
        api_url(FW_UPLOAD_JOB, id=job_id),
        status_code=http_status_code
    )

    # FW upload job - get metadata
    requests_mock.get(
        api_url(FW_UPLOAD_JOB, id=job_id),
        json={'firmware_image_id': firmware_image_id},
        status_code=http_status_code
    )
    # FW image - get URL
    requests_mock.get(
        api_url(FW_IMAGE, id=firmware_image_id),
        json={'datafile': 'https://my-fw.url.com'},
        status_code=http_status_code
    )
    # FW image - delete
    requests_mock.delete(
        api_url(FW_IMAGE, id=firmware_image_id),
        status_code=http_status_code
    )

    # -------------------------------------------------------------------------
    #                      Manifest upload URL mocks
    # -------------------------------------------------------------------------
    manifest_id = 987
    # Manifest upload
    requests_mock.post(
        api_url(FW_MANIFESTS),
        json={'id': manifest_id},
        status_code=http_status_code
    )

    # Manifest delete
    requests_mock.delete(
        api_url(FW_MANIFEST, id=manifest_id),
        status_code=http_status_code
    )

    # -------------------------------------------------------------------------
    #                      Update campaign URL mocks
    # -------------------------------------------------------------------------
    campaign_id = 963

    # Campaign create
    requests_mock.post(
        api_url(FW_CAMPAIGNS),
        json={'id': campaign_id},
        status_code=http_status_code
    )

    # Campaign delete
    requests_mock.delete(
        api_url(FW_CAMPAIGN, id=campaign_id),
        status_code=http_status_code
    )

    # Campaign stop
    requests_mock.post(
        api_url(FW_CAMPAIGN_STOP, id=campaign_id),
        status_code=http_status_code
    )

    # Campaign start
    requests_mock.post(
        api_url(FW_CAMPAIGN_START, id=campaign_id),
        status_code=http_status_code
    )

    # Campaign get metadata
    requests_mock.get(
        api_url(FW_CAMPAIGN, id=campaign_id),
        json={
            'phase': phase,
            'state': state,
            'autostop_reason': 'some conflict'
        },
        status_code=http_status_code
    )

    # Campaign devices
    requests_mock.get(
        api_url(FW_CAMPAIGN_DEV_METADATA, id=campaign_id),
        json={
            'data': [
                {
                    'deployment_state': deployment_state,
                    'device_id': 'xxxx-device-id-xxxx'
                },
                {
                    'deployment_state': deployment_state,
                    'device_id': 'yyyy-device-id-yyyy'
                }
            ]
        },
        status_code=http_status_code
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
def test_cli_update_delta_happy_day(happy_day_data, action, requests_mock):
    mock_update_apis(requests_mock)

    assert 0 == _common(
        happy_day_data,
        action,
        happy_day_data['delta_file']
    )


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_full_timeout(happy_day_data, action, requests_mock):
    """
    Campaign timeout case - campaign never reaches autostopped state
    """
    mock_update_apis(requests_mock, state='scheduled')
    with pytest.raises(AssertionError) as exc_info:
        _common(
            happy_day_data,
            action,
            happy_day_data['fw_file']
        )
    assert exc_info.value.args[0] == 'Campaign timed out'


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_conflict(happy_day_data, action, requests_mock):
    """
    Campaign conflict - campaign will be created in draft state
    """
    mock_update_apis(requests_mock, phase='draft')
    with pytest.raises(AssertionError) as exc_info:
        _common(
            happy_day_data,
            action,
            happy_day_data['fw_file']
        )
    assert 'Campaign not started' in exc_info.value.args[0]
    assert 'some conflict' in exc_info.value.args[0]

@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_failed_device(happy_day_data, action, requests_mock):
    """
    Campaign conflict - campaign will be created in draft state
    """
    mock_update_apis(requests_mock, deployment_state='failed')
    with pytest.raises(AssertionError) as exc_info:
        _common(
            happy_day_data,
            action,
            happy_day_data['fw_file']
        )
    assert 'Failed to update following devices' in exc_info.value.args[0]
    assert 'xxxx-device-id-xxxx' in exc_info.value.args[0]
    assert 'yyyy-device-id-yyyy' in exc_info.value.args[0]