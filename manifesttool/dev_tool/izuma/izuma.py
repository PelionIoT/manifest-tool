# ----------------------------------------------------------------------------
# Copyright 2019-2021
# Copyright 2022-2023 Izuma Networks
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
"""Communication with Izuma service."""
import base64
import hashlib
import logging
import time
import urllib.parse
from pathlib import Path
from typing import List, NewType

import requests
import yaml

# APIs documentation:
# https://developer.izumanetworks.com/docs/device-management/current/service-api-references/service-api-documentation.html
# Device directory -
#   https://developer.izumanetworks.com/docs/device-management-api/device-directory
# Update Service -
#   https://developer.izumanetworks.com/docs/device-management-api/update-service

DEVICES = "v3/devices"
DEVICE = "v3/devices/{id}"

FW_IMAGES = "/v3/firmware-images"
FW_IMAGE = "/v3/firmware-images/{id}"
FW_UPLOAD = FW_IMAGES
FW_UPLOAD_JOBS = "/v3/firmware-images/upload-jobs"
FW_UPLOAD_JOB = "/v3/firmware-images/upload-jobs/{id}"
FW_UPLOAD_JOB_CHUNK = "/v3/firmware-images/upload-jobs/{id}/chunks"

FW_MANIFESTS = "/v3/firmware-manifests"
FW_MANIFEST = "/v3/firmware-manifests/{id}"

FW_CAMPAIGNS = "/v3/update-campaigns"
FW_CAMPAIGN = "/v3/update-campaigns/{id}"
FW_CAMPAIGN_STOP = "/v3/update-campaigns/{id}/stop"
FW_CAMPAIGN_START = "/v3/update-campaigns/{id}/start"
FW_CAMPAIGN_STATISTICS = "/v3/update-campaigns/{id}/statistics"
FW_CAMPAIGN_STATISTICS_EVENTS = (
    "/v3/update-campaigns/{id}/statistics/{summary_id}/event_types"
)
FW_CAMPAIGN_DEV_METADATA = "/v3/update-campaigns/{id}/campaign-device-metadata"

CAMPAIGN_ACTIVE_PHASES = ["starting", "active"]

CAMPAIGN_NOT_STARTED_PHASES = ["draft", "stopped"]

FW_UPLOAD_MAX_SMALL_SIZE = int(100 * 1024 * 1024)

# must be greater than 5MB - AWS limitation
FW_UPLOAD_CHUNK_SIZE = int(6 * 1024 * 1024)

LOG = logging.getLogger("izuma")

URL = NewType("URL", str)
ID = NewType("ID", str)
Phase = NewType("Phase", str)

GET_TIMEOUT = 15 * 60
POST_TIMEOUT = 15 * 60
DEL_TIMEOUT = 5 * 60


class IzumaServiceApi:
    """Class for communication with Izuma service."""

    def __init__(self, config_file: Path):
        """
        Create REST API provider for Update Service APIs.

        :param host: Izuma service URL
        :param access_key: account access key
        """
        config = {}
        if config_file.is_file():
            with config_file.open("rt") as fh:
                config = yaml.safe_load(fh)
                if "access_key" not in config and "api_key" in config:
                    # replace api_key with access_key
                    # for backward compatibility
                    config["access_key"] = config.pop("api_key")

        if "host" in config and "access_key" in config:
            self._host = config["host"]
            self._default_headers = {
                "Authorization": "Bearer {}".format(config["access_key"])
            }
            return

        raise AssertionError(
            "Izuma service configurations "
            "(URL and access key) are not provided"
        )

    def _url(self, api, **kwargs) -> str:
        """
        Construct full REST API URL.

        Concatenates Izuma host URL with the desired REST API url and expands
        any patterns present in the URL (e.g. v3/manifests/{id})
        :param api: REST API URL part
        :param kwargs: dictionary for expanding the the URL patterns
        :return: full URL
        """
        if kwargs:
            return urllib.parse.urljoin(self._host, api.format(**kwargs))
        return urllib.parse.urljoin(self._host, api)

    def _headers(self, extra_headers: dict = None) -> dict:
        """
        Create request header.

        Initializes a dictionary with common headers and allows extending it
        with REST API specific data
        :param extra_headers: dictionary containing extra headers to be sent as
        part of REST API request
        :return: headers dictionary
        """
        copy = self._default_headers.copy()
        if extra_headers:
            copy.update(extra_headers)
        return copy

    @staticmethod
    def _chunk_md5(chunk: bytes) -> str:
        """
        Calculate MD5 digest over bytes.

        :param chunk: bytes to be processed
        :return: base64 encoded MD5 digest
        """
        return base64.b64encode(hashlib.md5(chunk).digest()).decode()  # nosec

    @staticmethod
    def _print_upload_progress(current: int, total: int):
        """
        Print upload progress.

        :param current: bytes uploaded so far
        :param total: uploaded file size
        """
        if total < FW_UPLOAD_CHUNK_SIZE:
            return
        increments = 50
        progress = (current / total) * 100
        count = int(progress // (100 / increments))
        text = "\r[{0: <{1}}] {2:.2f}%".format(
            "=" * count, increments, progress
        )
        print(text, end="\n" if progress == 100 else "")

    def fw_upload(self, fw_name: str, image: Path, encrypt: bool) -> dict:
        """
        Upload FW image.

        :param fw_name: update candidate image name as will appear on
               Izuma portal
        :param image: candidate FW image
        :param encrypt: request to encrypt FW image
        :return: uploaded image meta
        """
        fw_size = image.stat().st_size

        if fw_size < FW_UPLOAD_MAX_SMALL_SIZE:
            fw_meta = self._upload_small_image(fw_name, image, encrypt)
        else:
            fw_meta = self._upload_big_image(fw_name, fw_size, image, encrypt)

        LOG.info("Uploaded FW image %s", fw_meta["datafile"])
        return fw_meta

    def _upload_image_chunk(self, chunk: bytes, job_id: ID):
        """
        Upload FW image chunk.

        :param chunk: FW image chunk to be uploaded
        :param job_id: upload job ID
        """
        response = requests.post(
            self._url(FW_UPLOAD_JOB_CHUNK, id=job_id),
            headers=self._headers(
                {
                    "Content-Type": "binary/octet-stream",
                    "Content-MD5": self._chunk_md5(chunk),
                }
            ),
            data=chunk,
            timeout=POST_TIMEOUT,
        )
        response.raise_for_status()

    def _upload_big_image(
        self, fw_name: str, fw_size: int, image: Path, encrypt: bool
    ) -> dict:
        """
        Upload small FW image.

        :param fw_name: fw name as appears on the portal
        :param image: candidate FW image
        :param encrypt: Request to encrypt FW image
        :return: uploaded image meta
        """
        job_id = None
        try:
            with image.open("rb") as fh:
                job_id = self._create_upload_job(fw_name, encrypt)
                self._print_upload_progress(0, fw_size)
                upload_counter = 0
                while True:
                    chunk = fh.read(FW_UPLOAD_CHUNK_SIZE)
                    upload_counter += len(chunk)
                    self._upload_image_chunk(chunk, job_id)
                    self._print_upload_progress(upload_counter, fw_size)
                    if not chunk:
                        break
            LOG.debug("FW upload job %s completed", job_id)
            return self._get_fw_image_meta(job_id)
        except requests.HTTPError:
            LOG.error("FW image upload failed")
            raise
        finally:
            if job_id:
                self._delete_upload_job(job_id)

    def _upload_small_image(
        self, fw_name: str, image: Path, encrypt: bool
    ) -> dict:
        """
        Upload small FW image.

        :param fw_name: fw name as appears on the portal
        :param image: candidate FW image
        :param encrypt: Request to encrypt FW image
        :return: uploaded image meta
        """
        with image.open("rb") as fh:
            response = requests.post(
                self._url(FW_UPLOAD),
                headers=self._headers(),
                files={
                    "datafile": (image.name, fh),
                },
                data={"name": fw_name, "datafile_encryption": encrypt},
                timeout=POST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()

    def _get_fw_image_meta(self, job_id: ID) -> dict:
        """
        Extract uploaded image URL and ID.

        :param job_id: upload job ID
        :return: uploaded image meta
        """
        response = requests.get(
            self._url(FW_UPLOAD_JOB, id=job_id),
            headers=self._headers(),
            timeout=GET_TIMEOUT,
        )
        response.raise_for_status()
        image_id = response.json()["firmware_image_id"]
        response = requests.get(
            self._url(FW_IMAGE, id=image_id),
            headers=self._headers(),
            timeout=GET_TIMEOUT,
        )
        response.raise_for_status()

        return response.json()

    def _delete_upload_job(self, job_id: ID):
        """
        Delete a firmware image upload job.

        :param job_id: upload job ID
        """
        response = requests.delete(
            self._url(FW_UPLOAD_JOB, id=job_id),
            headers=self._headers(),
            timeout=DEL_TIMEOUT,
        )
        response.raise_for_status()
        LOG.debug("FW upload job %s deleted", job_id)

    def _create_upload_job(self, fw_name: str, encrypt: bool) -> ID:
        """
        Create a firmware image upload job.

        :param fw_name: fw name as appears on the portal
        :param encrypt: Request to encrypt FW image
        :return: upload job ID
        """
        response = requests.post(
            self._url(FW_UPLOAD_JOBS),
            headers=self._headers(),
            json={"name": fw_name, "datafile_encryption": encrypt},
            timeout=POST_TIMEOUT,
        )
        response.raise_for_status()
        response_data = response.json()
        job_id = response_data["id"]
        LOG.debug("FW upload job created %s", job_id)
        return job_id

    def fw_delete(self, image_id: ID):
        """
        Delete candidate image from Izuma portal.

        :param image_id: image ID as appears on the portal
        """
        response = requests.delete(
            self._url(FW_IMAGE, id=image_id),
            headers=self._headers(),
            timeout=DEL_TIMEOUT,
        )
        response.raise_for_status()
        LOG.info("Deleted FW image %s", image_id)

    def manifest_upload(self, name: str, manifest: Path) -> ID:
        """
        Upload manifest file to Izuma service.

        :param name: manifest name as will appear on Izuma portal
        :param manifest: manifest file
        :return: manifest ID as reported by portal
        """
        try:
            with manifest.open("rb") as fh:
                response = requests.post(
                    self._url(FW_MANIFESTS),
                    headers=self._headers(),
                    files={
                        "datafile": (manifest.name, fh),
                    },
                    data={"name": name},
                    timeout=POST_TIMEOUT,
                )
                response.raise_for_status()
                manifest_id = response.json()["id"]
                LOG.info("Uploaded manifest ID: %s", manifest_id)
                return manifest_id
        except requests.HTTPError:
            LOG.error("Failed to upload manifest")
            raise

    def manifest_delete(self, manifest_id: ID):
        """
        Delete manifest file from Izuma portal.

        :param manifest_id: manifest ID to be deleted
        """
        response = requests.delete(
            self._url(FW_MANIFEST, id=manifest_id),
            headers=self._headers(),
            timeout=DEL_TIMEOUT,
        )
        response.raise_for_status()
        LOG.info("Deleted manifest ID: %s", manifest_id)

    def campaign_create(
        self, name: str, manifest_id: ID, device_filter: str
    ) -> ID:
        """
        Create update campaign on Izuma portal.

        :param name: campaign name as will appear on Izuma portal
        :param manifest_id: manifest ID as
        :param device_filter: device filter query
        :return: campaign ID as reported by portal
        """
        try:
            response = requests.post(
                self._url(FW_CAMPAIGNS),
                headers=self._headers(),
                json={
                    "campaign_strategy": "one-shot",
                    "description": "Development campaign",
                    "device_filter": device_filter,
                    "name": name,
                    "root_manifest_id": manifest_id,
                },
                timeout=POST_TIMEOUT,
            )
            response.raise_for_status()
            campaign_id = response.json()["id"]
            LOG.info("Created Campaign ID: %s", campaign_id)
            return campaign_id
        except requests.HTTPError:
            LOG.error("Failed to create campaign")
            raise

    def campaign_delete(self, campaign_id: ID):
        """
        Delete inactive (stopped/draft) update campaign.

        :param campaign_id: campaign ID
        """
        response = requests.delete(
            self._url(FW_CAMPAIGN, id=campaign_id),
            headers=self._headers(),
            timeout=DEL_TIMEOUT,
        )
        response.raise_for_status()
        LOG.info("Deleted campaign %s", campaign_id)

    def campaign_stop(self, campaign_id: ID, timeout: int = 60):
        """
        Stop update campaign.

        :param campaign_id: campaign ID
        :param timeout: timeout in seconds to wait for campaign to stop
        """
        try:
            # check campaign phase and skip if it not active
            curr_phase = self.campaign_get(campaign_id)["phase"]
            if not self.campaign_is_active(curr_phase):
                return
            # send request to stop
            response = requests.post(
                self._url(FW_CAMPAIGN_STOP, id=campaign_id),
                headers=self._headers(),
                timeout=POST_TIMEOUT,
            )
            response.raise_for_status()
            curr_phase = self.campaign_get(campaign_id)["phase"]
            # The campaign is stopping. wait for it to stop
            retries = timeout
            while curr_phase == "stopping" and retries > 0:
                time.sleep(1)
                curr_phase = self.campaign_get(campaign_id)["phase"]
                retries -= 1
            if retries == 0:
                LOG.debug("Stopping Campaign timed out")
            LOG.info("Stopped campaign %s", campaign_id)
        except requests.HTTPError as ex:
            # ignore error from stop campaign as it may already be stopped
            LOG.debug("Failed stopping campaign - %s", ex)

    def campaign_start(self, campaign_id: ID):
        """
        Start update campaign.

        :param campaign_id: campaign ID
        """
        response = requests.post(
            self._url(FW_CAMPAIGN_START, id=campaign_id),
            headers=self._headers(),
            timeout=POST_TIMEOUT,
        )
        response.raise_for_status()

    def campaign_get(self, campaign_id: ID) -> dict:
        """
        Get an update campaign current representation/state.

        :param campaign_id:
        :return: Dictionary with current update campaign state
        """
        response = requests.get(
            self._url(FW_CAMPAIGN, id=campaign_id),
            headers=self._headers(),
            timeout=GET_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()

    def campaign_statistics(self, campaign_id: ID) -> List[dict]:
        """
        Get campaign statistics.

        :param campaign_id: campaign ID
        :return: List of statistics for a campaign
        """
        try:
            response = requests.get(
                self._url(FW_CAMPAIGN_STATISTICS, id=campaign_id),
                headers=self._headers(),
                timeout=GET_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()["data"]
        except requests.HTTPError:
            pass
        return []

    def campaign_statistic_events(
        self, campaign_id: ID, summary_id: str
    ) -> List[dict]:
        """
        Get campaign events grouped by summary.

        :param campaign_id: campaign ID
        :param summary_id: The summary status
            Available values: fail, success, info, skipped
        :return: List of statistics for a campaign
        """
        try:
            response = requests.get(
                self._url(
                    FW_CAMPAIGN_STATISTICS_EVENTS,
                    id=campaign_id,
                    summary_id=summary_id,
                ),
                headers=self._headers(),
                timeout=GET_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()["data"]
        except requests.HTTPError:
            pass
        return []

    def campaign_device_metadata(self, campaign_id: ID) -> List[dict]:
        """
        Get metadata for devices participating in update campaign.

        Note: this function and assumes small number of devices participating
        in update campaign (as part of developer flow). Thus it does not
        handles pagination
        :param campaign_id: campaign ID
        :return: List of device metadata dictionaries for devices participating
        in update campaign
        """
        response = requests.get(
            self._url(FW_CAMPAIGN_DEV_METADATA, id=campaign_id),
            headers=self._headers(),
            timeout=GET_TIMEOUT,
        )
        response.raise_for_status()
        return response.json()["data"]

    @staticmethod
    def campaign_is_active(phase: Phase) -> bool:
        """
        Understand if update campaign is in active phase.

        :param phase: current update campaign phase
        :return: True if update campaign phase is starting or active
        """
        return phase in CAMPAIGN_ACTIVE_PHASES

    @staticmethod
    def campaign_is_not_started(phase: Phase) -> bool:
        """
        Understand if update campaign is not started phase.

        :param phase: current update campaign phase
        :return: True if update campaign phase is starting or active
        """
        return phase in CAMPAIGN_NOT_STARTED_PHASES

    def device_delete(self, device_id: ID):
        """
        Delete device with a developer certificate.

        :param device_id: device ID
        """
        response = requests.delete(
            self._url(DEVICE, id=device_id),
            headers=self._headers(),
            timeout=DEL_TIMEOUT,
        )
        response.raise_for_status()
        LOG.info("Deleted device %s", device_id)

    def _get_objects(self, api_url: str, api_filter: str = "") -> dict:
        """
        Get list of objects for the account.

        :param api_filter: filter query string
        :return: Dictionary with the list of objects
        """
        api_filter = "&filter={}".format(api_filter) if api_filter else ""
        url = "{}?limit=1000&include=total_count{}".format(api_url, api_filter)
        response = requests.get(
            self._url(url), headers=self._headers(), timeout=GET_TIMEOUT
        )
        response.raise_for_status()
        total_count = response.json()["total_count"]
        objects = response.json()["data"]
        LOG.debug("Got %d/%d objects", len(objects), total_count)

        url = url + "&after={after}"
        while len(objects) < total_count:
            last_object_id = objects[-1]["id"]
            response = requests.get(
                self._url(url, after=last_object_id),
                headers=self._headers(),
                timeout=GET_TIMEOUT,
            )
            response.raise_for_status()
            objects.extend(response.json()["data"])
            LOG.debug("Got %d/%d objects", len(objects), total_count)

        return objects

    def get_devices(self, api_filter: str = "") -> dict:
        """
        Get list of devices for the account.

        :param api_filter: filter query string
        :return: Dictionary with the list of devices
        """
        return self._get_objects(DEVICES, api_filter)

    def get_fw_images(self, api_filter: str = "") -> dict:
        """
        Get list of firmware images for the account.

        :param api_filter: filter query string
        :return: Dictionary with the list of firmware images
        """
        return self._get_objects(FW_IMAGES, api_filter)

    def get_manifests(self, api_filter: str = "") -> dict:
        """
        Get list of manifests for the account.

        :param api_filter: filter query string
        :return: Dictionary with the list of manifests
        """
        return self._get_objects(FW_MANIFESTS, api_filter)

    def get_campaigns(self, api_filter: str = "") -> dict:
        """
        Get list of campaigns for the account.

        :param api_filter: filter query string
        :return: Dictionary with the list of campaigns
        """
        return self._get_objects(FW_CAMPAIGNS, api_filter)
