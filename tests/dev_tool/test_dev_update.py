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
import urllib
from typing import Optional, Union, Tuple

import pytest
import yaml
import re

from manifesttool.dev_tool import dev_tool
from manifesttool.dev_tool.izuma import izuma
from tests.conftest import working_directory
from tests.conftest import data_generator


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
            "https://api.us-east-1.mbedcloud.com", api.format(**kwargs)
        )
    return urllib.parse.urljoin("https://api.us-east-1.mbedcloud.com", api)


class CampaignFsm:
    CAMPAIGN_STATUSES = [
        (izuma.Phase("draft"), "draft"),
        (izuma.Phase("starting"), "scheduled"),
        (izuma.Phase("active"), "publishing"),
        (izuma.Phase("active"), "publishing"),
        (izuma.Phase("active"), "publishing"),
        (izuma.Phase("stopping"), "stopping"),
        (izuma.Phase("stopped"), "auto_stopped"),
    ]

    PHASE_DRAFT = 0
    PHASE_ACTIVE = 2

    def __init__(
        self, campaign_id: int, last_phase_in_test: Optional[int] = None
    ):
        self.campaign_id = campaign_id
        self.current_idx = 0
        if last_phase_in_test is not None:
            self.last_idx = last_phase_in_test
        else:
            self.last_idx = len(self.CAMPAIGN_STATUSES) - 1

    def next_phase(self) -> Tuple[izuma.Phase, str]:
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
    return {"id": g_curr_campaign.get().campaign_id}


def campaign_start_callback(_request, _context):
    g_curr_campaign.get().start()


def campaign_stop_callback(_request, _context):
    g_curr_campaign.get().stop()


def campaign_get_callback(_request, _context):
    phase, state = g_curr_campaign.get().next_phase()
    return {"phase": phase, "state": state, "autostop_reason": "NA"}


def campaign_delete_callback(_request, _context):
    g_curr_campaign.set(None)


def mock_update_apis(
    requests_mock,
    last_phase_in_test=None,
    deployment_state="deployed",
    http_status_code=200,
    encrypted_payload=False,
):
    job_id = 123
    firmware_image_id = 654
    # -------------------------------------------------------------------------
    #                        FW image upload URL mocks
    # -------------------------------------------------------------------------

    # FW upload job - create
    requests_mock.post(
        api_url(izuma.FW_UPLOAD_JOBS),
        json={"id": job_id},
        status_code=http_status_code,
    )

    # FW upload job - upload chunk
    requests_mock.post(
        api_url(izuma.FW_UPLOAD_JOB_CHUNK, id=job_id),
        status_code=http_status_code,
    )

    # FW upload job - delete
    requests_mock.delete(
        api_url(izuma.FW_UPLOAD_JOB, id=job_id), status_code=http_status_code
    )

    # FW upload job - get metadata
    requests_mock.get(
        api_url(izuma.FW_UPLOAD_JOB, id=job_id),
        json={"firmware_image_id": firmware_image_id},
        status_code=http_status_code,
    )

    # FW image - meta response
    fw_meta_res = {
        "datafile": "https://my-fw.url.com/fw_image.bin",
        "short_datafile": "/fw/fw_image.bin",
        "id": firmware_image_id,
    }
    if encrypted_payload:
        fw_meta_res["datafile_encryption"] = True
        fw_meta_res["encrypted_datafile_checksum"] = "AB" * 32
        fw_meta_res["encrypted_datafile_size"] = 123

    # FW image - get URL
    requests_mock.get(
        api_url(izuma.FW_IMAGE, id=firmware_image_id),
        json=fw_meta_res,
        status_code=http_status_code,
    )

    # FW one shot upload
    requests_mock.post(
        api_url(izuma.FW_UPLOAD),
        json=fw_meta_res,
        status_code=http_status_code,
    )

    # FW image - delete
    requests_mock.delete(
        api_url(izuma.FW_IMAGE, id=firmware_image_id),
        status_code=http_status_code,
    )

    # -------------------------------------------------------------------------
    #                      Manifest upload URL mocks
    # -------------------------------------------------------------------------
    manifest_id = 987
    # Manifest upload
    requests_mock.post(
        api_url(izuma.FW_MANIFESTS),
        json={"id": manifest_id},
        status_code=http_status_code,
    )

    # Manifest delete
    requests_mock.delete(
        api_url(izuma.FW_MANIFEST, id=manifest_id),
        status_code=http_status_code,
    )

    # -------------------------------------------------------------------------
    #                      Update campaign URL mocks
    # -------------------------------------------------------------------------
    campaign_id = 963

    g_curr_campaign.set(CampaignFsm(campaign_id, last_phase_in_test))

    # Campaign create
    requests_mock.post(
        api_url(izuma.FW_CAMPAIGNS),
        json=campaign_create_callback,
        status_code=http_status_code,
    )

    # Campaign delete
    requests_mock.delete(
        api_url(izuma.FW_CAMPAIGN, id=campaign_id),
        json=campaign_delete_callback,
        status_code=http_status_code,
    )

    # Campaign stop
    requests_mock.post(
        api_url(izuma.FW_CAMPAIGN_STOP, id=campaign_id),
        json=campaign_stop_callback,
        status_code=http_status_code,
    )

    # Campaign start
    requests_mock.post(
        api_url(izuma.FW_CAMPAIGN_START, id=campaign_id),
        json=campaign_start_callback,
        status_code=http_status_code,
    )

    # Campaign get metadata
    requests_mock.get(
        api_url(izuma.FW_CAMPAIGN, id=campaign_id),
        json=campaign_get_callback,
        status_code=http_status_code,
    )

    # Campaign statistics
    requests_mock.get(
        api_url(izuma.FW_CAMPAIGN_STATISTICS, id=campaign_id),
        json={
            "data": [
                {
                    "id": "fail",
                    "campaign_id": str(campaign_id),
                    "summary_status": "FAIL",
                    "count": 2 if deployment_state != "deployed" else 0,
                    "created_at": "NA",
                    "object": "summary_status",
                },
                {
                    "id": "info",
                    "campaign_id": str(campaign_id),
                    "summary_status": "INFO",
                    "count": 0,
                    "created_at": "NA",
                    "object": "summary_status",
                },
                {
                    "id": "skipped",
                    "campaign_id": str(campaign_id),
                    "summary_status": "SKIPPED",
                    "count": 0,
                    "created_at": "NA",
                    "object": "summary_status",
                },
                {
                    "id": "success",
                    "campaign_id": str(campaign_id),
                    "summary_status": "SUCCESS",
                    "count": 2 if deployment_state == "deployed" else 0,
                    "created_at": "NA",
                    "object": "summary_status",
                },
            ]
        },
        status_code=http_status_code,
    )

    # Campaign statistics fail events
    requests_mock.get(
        api_url(
            izuma.FW_CAMPAIGN_STATISTICS_EVENTS,
            id=campaign_id,
            summary_id="fail",
        ),
        json={
            "data": [
                {
                    "created_at": "NA",
                    "event_type": "NA",
                    "description": "Update error, failed",
                    "summary_status": "FAIL",
                    "id": "NA",
                    "count": 2,
                    "summary_status_id": "fail",
                    "campaign_id": str(campaign_id),
                }
            ]
        },
        status_code=http_status_code,
    )

    # Campaign statistics skipped events
    requests_mock.get(
        api_url(
            izuma.FW_CAMPAIGN_STATISTICS_EVENTS,
            id=campaign_id,
            summary_id="skipped",
        ),
        json={
            "data": [
                {
                    "created_at": "NA",
                    "event_type": "NA",
                    "description": "Update skipped, skipped",
                    "summary_status": "SKIPPED",
                    "id": "NA",
                    "count": 2,
                    "summary_status_id": "skipped",
                    "campaign_id": str(campaign_id),
                }
            ]
        },
        status_code=http_status_code,
    )

    # Campaign devices
    requests_mock.get(
        api_url(izuma.FW_CAMPAIGN_DEV_METADATA, id=campaign_id),
        json={
            "data": [
                {
                    "campaign": str(campaign_id),
                    "created_at": "NA",
                    "deployment_state": deployment_state,
                    "description": "",
                    "device_id": "xxxx-device-id-xxxx",
                    "etag": "NA",
                    "id": "NA",
                    "mechanism": "connector",
                    "mechanism_url": "",
                    "name": "xxxx-device-id-xxxx",
                    "object": "update-campaign-device-metadata",
                    "updated_at": "NA",
                },
                {
                    "campaign": str(campaign_id),
                    "created_at": "NA",
                    "deployment_state": deployment_state,
                    "description": "",
                    "device_id": "yyyy-device-id-yyyy",
                    "etag": "NA",
                    "id": "NA",
                    "mechanism": "connector",
                    "mechanism_url": "",
                    "name": "yyyy-device-id-yyyy",
                    "object": "update-campaign-device-metadata",
                    "updated_at": "NA",
                },
            ]
        },
        status_code=http_status_code,
    )


def _common(happy_day_data, action, payload_path):
    cmd = (
        ["--debug"]
        + action
        + [
            "--cache-dir",
            happy_day_data["tmp_path"].as_posix(),
            "--payload-path",
            payload_path.as_posix(),
            "--vendor-data",
            happy_day_data["dev_cfg"].as_posix(),
            "--wait-for-completion",
            "--timeout",
            "10",
            "--device-id",
            "1234",
        ]
    )
    if "-fw-version" not in action and "--fw-migrate-ver" not in action:
        if action[0] == "update-v1":
            cmd.extend(["--fw-version", "100500"])
        else:
            cmd.extend(["--fw-version", "100.500.666"])

    with working_directory(happy_day_data["tmp_path"]):
        return dev_tool.entry_point(cmd)


@pytest.mark.parametrize(
    "payload_path,force_chunks,action,external_signing_tool",
    [
        ("fw_file", True, ["update"], True),
        ("fw_file", False, ["update", "--sign-image"], False),
        ("fw_file", False, ["update", "--encrypt-payload"], False),
        ("fw_file", False, ["update", "--combined-image"], False),
        ("delta_file", False, ["update"], False),
        ("delta_file", False, ["update"], True),
        ("delta_file", False, ["update", "--sign-image"], False),
        ("fw_file", False, ["update-v1"], True),
        ("fw_file", False, ["update-v1"], False),
        ("delta_file", False, ["update-v1"], True),
        ("delta_file", False, ["update-v1"], False),
    ],
)
def test_cli_update_happy_day(
    tmp_path_factory,
    payload_path,
    force_chunks,
    action,
    external_signing_tool,
    requests_mock,
    timeless,
    monkeypatch,
    caplog,
):
    _ = timeless
    mock_update_apis(
        requests_mock, encrypted_payload=("--encrypt-payload" in action)
    )

    happy_day_data = data_generator(
        tmp_path_factory, size=512, signing_tool=external_signing_tool
    )

    if force_chunks:
        monkeypatch.setattr(
            izuma, "FW_UPLOAD_MAX_SMALL_SIZE", 10, raising=True
        )
        monkeypatch.setattr(izuma, "FW_UPLOAD_CHUNK_SIZE", 10, raising=True)

    assert _common(happy_day_data, action, happy_day_data[payload_path]) == 0
    assert caplog.messages[-8:] == [
        "----------------------------",
        "    Campaign Summary ",
        "----------------------------",
        " Successfully updated:   2",
        " Failed to update:       0",
        " Skipped:                0",
        " Pending:                0",
        " Total in this campaign: 2",
    ]

    # If external signing tool is defined, check if it indeed is running
    if external_signing_tool:
        # load dev_cfg
        with (happy_day_data["dev_cfg"]).open("rt") as fh:
            dev_cfg = yaml.safe_load(fh)

        expected_message = r"^Running {} {} {} (.+?) to sign manifest.".format(
            dev_cfg["signing-tool"], "sha256", dev_cfg["signing-key-id"]
        )
        matching_messages = [
            message
            for message in caplog.messages
            if re.match(expected_message, message)
        ]

        assert matching_messages


@pytest.mark.parametrize(
    "action",
    [
        ["update"],
        ["update", "--sign-image"],
        ["update", "--combined-image"],
        ["update-v1"],
    ],
)
def test_cli_update_full_timeout(
    happy_day_data, action, requests_mock, timeless, caplog
):
    """
    Campaign timeout case - campaign never reaches stopped phase
    """
    _ = timeless
    mock_update_apis(
        requests_mock, last_phase_in_test=CampaignFsm.PHASE_ACTIVE
    )
    assert _common(happy_day_data, action, happy_day_data["fw_file"]) == 1
    assert caplog.messages[-1] == "Campaign timed out"


@pytest.mark.parametrize(
    "action",
    [
        ["update"],
        ["update", "--sign-image"],
        ["update", "--combined-image"],
        ["update-v1"],
    ],
)
def test_cli_update_conflict(
    happy_day_data, action, requests_mock, timeless, caplog
):
    """
    Campaign conflict - campaign will be created in draft state
    """
    _ = timeless
    mock_update_apis(requests_mock, last_phase_in_test=CampaignFsm.PHASE_DRAFT)
    assert _common(happy_day_data, action, happy_day_data["fw_file"]) == 1
    assert (
        caplog.messages[-1]
        == "Campaign not started - check filter and campaign state.\nReason: NA"  # noqa: E501
    )


@pytest.mark.parametrize(
    "action",
    [
        ["update"],
        ["update", "--sign-image"],
        ["update-v1"],
        ["update", "--combined-image"],
    ],
)
def test_cli_update_failed_device(
    happy_day_data, action, requests_mock, timeless, caplog
):
    """
    Campaign conflict - campaign will be created in draft state
    """
    _ = timeless
    mock_update_apis(requests_mock, deployment_state="failed")
    assert _common(happy_day_data, action, happy_day_data["fw_file"]) == 1
    assert caplog.messages[-11:] == [
        "----------------------------",
        "    Campaign Summary ",
        "----------------------------",
        " Successfully updated:   0",
        " Failed to update:       2",
        " Skipped:                0",
        " Pending:                0",
        " Total in this campaign: 2",
        "Reasons for failed updates:",
        " Update error, failed",
        "Failed to update 2 devices: xxxx-device-id-xxxx, yyyy-device-id-yyyy",
    ]
