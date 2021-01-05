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
import urllib
from typing import Optional, Union

import pytest

from manifesttool.dev_tool import dev_tool
from manifesttool.dev_tool.pelion.pelion import *
from tests import conftest


# phase to state:
# draft -> draft
# starting -> scheduled
# starting -> allocating_quota
# starting -> allocated_quota
# stopped -> quota_allocation_failed
# starting -> checking_manifest
# starting -> checked_manifest
# starting -> device_fetch
# starting -> device_copy
# starting -> device_copy_complete
# starting -> device_check
# active -> publishing
# active -> deploying
# archived -> deployed
# stopping -> stopping
# stopped -> firmware_manifest_removed
# stopped -> expired
# stopped -> auto_stopped
# stopped -> user_stopped
# stopped -> conflict
# archived -> user_archived


def api_url(api, **kwargs):
    if kwargs:
        return urllib.parse.urljoin(
            'https://api.us-east-1.mbedcloud.com', api.format(**kwargs))
    return urllib.parse.urljoin('https://api.us-east-1.mbedcloud.com', api)


class CampaignFsm:
    CAMPAIGN_STATUSES = [
        (Phase('draft'), 'draft'),
        (Phase('starting'), 'scheduled'),
        (Phase('active'), 'publishing'),
        (Phase('stopping'), 'stopping'),
        (Phase('stopped'), 'auto_stopped')
    ]

    PHASE_DRAFT = 0
    PHASE_ACTIVE = 2

    def __init__(self, campaign_id: int, last_phase_in_test: Optional[int] = None):
        self.campaign_id = campaign_id
        self.current_idx = 0
        if last_phase_in_test is not None:
            self.last_idx = last_phase_in_test
        else:
            self.last_idx = len(self.CAMPAIGN_STATUSES) - 1

    def next_phase(self) -> Tuple[Phase, str]:
        if self.current_idx < self.last_idx:
            self.current_idx += 1
        # return Phase, State
        return self.CAMPAIGN_STATUSES[self.current_idx]

    def create(self):
        self.current_idx = 0

    def start(self):
        self.current_idx = 1 if self.last_idx > 0 else 0

    def stop(self):
        self.current_idx = len(self.CAMPAIGN_STATUSES) - 1


class CampaignContainer:

    def __init__(self):
        self.campaign = None

    def set(self, campaign: Union[CampaignFsm, None]):
        self.campaign = campaign

    def get(self) -> CampaignFsm:
        assert self.campaign
        return self.campaign


g_curr_campaign = CampaignContainer()


def campaign_create_callback(_request, _context):
    g_curr_campaign.get().create()
    return {'id': g_curr_campaign.get().campaign_id}


def campaign_start_callback(_request, _context):
    g_curr_campaign.get().start()


def campaign_stop_callback(_request, _context):
    g_curr_campaign.get().stop()


def campaign_get_callback(_request, _context):
    phase, state = g_curr_campaign.get().next_phase()
    return {'phase': phase, 'state': state, 'autostop_reason': 'NA'}


def campaign_delete_callback(_request, _context):
    g_curr_campaign.set(None)


def mock_update_apis(
        requests_mock,
        last_phase_in_test=None,
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

    g_curr_campaign.set(CampaignFsm(campaign_id, last_phase_in_test))

    # Campaign create
    requests_mock.post(
        api_url(FW_CAMPAIGNS),
        json=campaign_create_callback,
        status_code=http_status_code
    )

    # Campaign delete
    requests_mock.delete(
        api_url(FW_CAMPAIGN, id=campaign_id),
        json=campaign_delete_callback,
        status_code=http_status_code
    )

    # Campaign stop
    requests_mock.post(
        api_url(FW_CAMPAIGN_STOP, id=campaign_id),
        json=campaign_stop_callback,
        status_code=http_status_code
    )

    # Campaign start
    requests_mock.post(
        api_url(FW_CAMPAIGN_START, id=campaign_id),
        json=campaign_start_callback,
        status_code=http_status_code
    )

    # Campaign get metadata
    requests_mock.get(
        api_url(FW_CAMPAIGN, id=campaign_id),
        json=campaign_get_callback,
        status_code=http_status_code
    )

    # Campaign statistics
    requests_mock.get(
        api_url(FW_CAMPAIGN_STATISTICS, id=campaign_id),
        json={
            'data': [
                {
                    'id': 'fail',
                    'campaign_id': str(campaign_id),
                    'summary_status': 'FAIL',
                    'count': 2 if deployment_state != 'deployed' else 0,
                    'created_at': 'NA',
                    'object': 'summary_status'
                },
                {
                    'id': 'info',
                    'campaign_id': str(campaign_id),
                    'summary_status': 'INFO',
                    'count': 0,
                    'created_at': 'NA',
                    'object': 'summary_status'
                },
                {
                    'id': 'skipped',
                    'campaign_id': str(campaign_id),
                    'summary_status': 'SKIPPED',
                    'count': 0,
                    'created_at': 'NA',
                    'object': 'summary_status'
                },
                {
                    'id': 'success',
                    'campaign_id': str(campaign_id),
                    'summary_status': 'SUCCESS',
                    'count': 2 if deployment_state == 'deployed' else 0,
                    'created_at': 'NA',
                    'object': 'summary_status'
                }
            ]
        },
        status_code=http_status_code
    )

    # Campaign devices
    requests_mock.get(
        api_url(FW_CAMPAIGN_DEV_METADATA, id=campaign_id),
        json={
            'data': [
                {
                    'campaign': str(campaign_id),
                    'created_at': 'NA',
                    'deployment_state': deployment_state,
                    'description': '',
                    'device_id': 'xxxx-device-id-xxxx',
                    'etag': 'NA',
                    'id': 'NA',
                    'mechanism': 'connector',
                    'mechanism_url': '',
                    'name': 'xxxx-device-id-xxxx',
                    'object': 'update-campaign-device-metadata',
                    'updated_at': 'NA'
                },
                {
                    'campaign': str(campaign_id),
                    'created_at': 'NA',
                    'deployment_state': deployment_state,
                    'description': '',
                    'device_id': 'yyyy-device-id-yyyy',
                    'etag': 'NA',
                    'id': 'NA',
                    'mechanism': 'connector',
                    'mechanism_url': '',
                    'name': 'yyyy-device-id-yyyy',
                    'object': 'update-campaign-device-metadata',
                    'updated_at': 'NA'
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
def test_cli_update_delta_happy_day(happy_day_data, action, requests_mock, caplog):
    mock_update_apis(requests_mock)

    assert _common(
        happy_day_data,
        action,
        happy_day_data['delta_file']
    ) == 0
    assert caplog.messages[-8:] == [
        '----------------------------',
        '    Campaign Summary ',
        '----------------------------',
        ' Successfully updated:   2',
        ' Failed to update:       0',
        ' Skipped:                0',
        ' Pending:                0',
        ' Total in this campaign: 2'
    ]


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_full_timeout(happy_day_data, action, requests_mock, caplog):
    """
    Campaign timeout case - campaign never reaches stopped phase
    """
    mock_update_apis(requests_mock, last_phase_in_test=CampaignFsm.PHASE_ACTIVE)
    assert _common(
        happy_day_data,
        action,
        happy_day_data['fw_file']
    ) == 1
    assert caplog.messages[-1] == 'Campaign timed out'

@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_conflict(happy_day_data, action, requests_mock, caplog):
    """
    Campaign conflict - campaign will be created in draft state
    """
    mock_update_apis(requests_mock, last_phase_in_test=CampaignFsm.PHASE_DRAFT)
    assert _common(
        happy_day_data,
        action,
        happy_day_data['fw_file']
    ) == 1
    assert caplog.messages[-1] == 'Campaign not started - check filter and campaign state.\nReason: NA'


@pytest.mark.parametrize(
    'action',
    [
        ['update'],
        ['update', '--sign-image'],
        ['update-v1']
    ]
)
def test_cli_update_failed_device(happy_day_data, action, requests_mock, caplog):
    """
    Campaign conflict - campaign will be created in draft state
    """
    mock_update_apis(requests_mock, deployment_state='failed')
    assert _common(
        happy_day_data,
        action,
        happy_day_data['fw_file']
    ) == 1
    assert caplog.messages[-9:] == [
        '----------------------------',
        '    Campaign Summary ',
        '----------------------------',
        ' Successfully updated:   0',
        ' Failed to update:       2',
        ' Skipped:                0',
        ' Pending:                0',
        ' Total in this campaign: 2',
        'Failed to update 2 devices: xxxx-device-id-xxxx, yyyy-device-id-yyyy'
    ]
