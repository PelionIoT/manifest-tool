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
import base64
import hashlib
import logging
import time
import urllib.parse
from pathlib import Path
from typing import Tuple, NewType, List

import requests

FW_UPLOAD = '/v3/firmware-images'
FW_UPLOAD_JOBS = '/v3/firmware-images/upload-jobs'
FW_UPLOAD_JOB = '/v3/firmware-images/upload-jobs/{id}'
FW_UPLOAD_JOB_CHUNK = '/v3/firmware-images/upload-jobs/{id}/chunks'
FW_IMAGE = '/v3/firmware-images/{id}'

FW_MANIFESTS = '/v3/firmware-manifests'
FW_MANIFEST = '/v3/firmware-manifests/{id}'

FW_CAMPAIGNS = '/v3/update-campaigns'
FW_CAMPAIGN = '/v3/update-campaigns/{id}'
FW_CAMPAIGN_STOP = '/v3/update-campaigns/{id}/stop'
FW_CAMPAIGN_START = '/v3/update-campaigns/{id}/start'
FW_CAMPAIGN_STATISTICS = '/v3/update-campaigns/{id}/statistics'
FW_CAMPAIGN_DEV_METADATA = '/v3/update-campaigns/{id}/campaign-device-metadata'

CAMPAIGN_ACTIVE_PHASES = [
    'starting',
    'active'
]

FW_UPLOAD_MAX_SMALL_SIZE = int(100 * 1024 * 1024)

# must be greater than 5MB - AWS limitation
FW_UPLOAD_CHUNK_SIZE = int(6 * 1024 * 1024)

LOG = logging.getLogger('pelion')

URL = NewType('URL', str)
ID = NewType('ID', str)
Phase = NewType('Phase', str)

class UpdateServiceApi:
    def __init__(self, host: URL, api_key: str):
        """
        Create REST API provider for Update Service APIs
        :param host: Pelion service URL
        :param api_key: account API key
        """
        self._host = host
        self._default_headers = {
            'Authorization': 'Bearer {}'.format(api_key)
        }

    def _url(self, api, **kwargs) -> str:
        """
        Helper function for constructing full REST API URL

        Concatenates Pelion host URL with the desired REST API url and expands
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
        Helper function for creating request header

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
        Helper function for calculating MD5 digest over bytes
        :param chunk: bytes to be processed
        :return: base64 encoded MD5 digest
        """
        return base64.b64encode(hashlib.md5(chunk).digest()).decode()  # nosec

    @staticmethod
    def _print_upload_progress(current: int, total: int):
        """
        Helper function for printing upload progress
        :param current: bytes uploaded so far
        :param total: uploaded file size
        """
        if total < FW_UPLOAD_CHUNK_SIZE:
            return
        increments = 50
        progress = ((current / total) * 100)
        count = int(progress // (100 / increments))
        text = '\r[{0: <{1}}] {2:.2f}%'.format(
            '=' * count, increments, progress)
        print(text, end='\n' if progress == 100 else '')

    def fw_upload(self, fw_name: str, image: Path) -> Tuple[URL, str, ID]:
        """
        Upload FW image
        :param fw_name: update candidate image name as will appear on Pelion
               portal
        :param image: candidate FW image
        :return: tuple consisting of uploaded image URL, short image URL and ID
        """
        fw_size = image.stat().st_size

        if fw_size < FW_UPLOAD_MAX_SMALL_SIZE:
            fw_image_url, short_image_url, fw_image_id = \
                self._upload_small_image(fw_name, image)
        else:
            fw_image_url, short_image_url, fw_image_id = \
                self._upload_big_image(fw_name, fw_size, image)

        LOG.info('Uploaded FW image %s', fw_image_url)
        return fw_image_url, short_image_url, fw_image_id

    def _upload_image_chunk(self, chunk: bytes, job_id: ID):
        """
        Helper function for uploading FW image chunk
        :param chunk: FW image chunk to be uploaded
        :param job_id: upload job ID
        """
        response = requests.post(
            self._url(FW_UPLOAD_JOB_CHUNK, id=job_id),
            headers=self._headers(
                {
                    'Content-Type': 'binary/octet-stream',
                    'Content-MD5': self._chunk_md5(chunk)
                }
            ),
            data=chunk
        )
        response.raise_for_status()

    def _upload_big_image(self, fw_name: str, fw_size: int, image: Path) -> \
            Tuple[URL, str, ID]:
        """
        Helper function for uploading small FW image
        :param fw_name: fw name as appears on the portal
        :param image: candidate FW image
        :return: tuple consisting of uploaded image URL, short image URL and ID
        """
        job_id = None
        try:
            with image.open('rb') as fh:
                job_id = self._create_upload_job(fw_name)
                self._print_upload_progress(0, fw_size)
                upload_counter = 0
                while True:
                    chunk = fh.read(FW_UPLOAD_CHUNK_SIZE)
                    upload_counter += len(chunk)
                    self._upload_image_chunk(chunk, job_id)
                    self._print_upload_progress(upload_counter, fw_size)
                    if not chunk:
                        break
            LOG.debug('FW upload job %s completed', job_id)
            return self._get_fw_image_meta(job_id)
        except requests.HTTPError:
            LOG.error('FW image upload failed')
            raise
        finally:
            if job_id:
                self._delete_upload_job(job_id)

    def _upload_small_image(self, fw_name: str, image: Path) -> \
            Tuple[URL, str, ID]:
        """
        Helper function for uploading small FW image
        :param fw_name: fw name as appears on the portal
        :param image: candidate FW image
        :return: tuple consisting of uploaded image URL, short image URL and ID
        """
        with image.open('rb') as fh:
            response = requests.post(
                self._url(FW_UPLOAD),
                headers=self._headers(),
                files={
                    'datafile': (image.name, fh),
                },
                data={
                    'name': fw_name
                }
            )
            response.raise_for_status()
            fw_image_url = response.json()['datafile']
            short_image_url = response.json()['short_datafile']
            fw_image_id = response.json()['id']
            return fw_image_url, short_image_url, fw_image_id

    def _get_fw_image_meta(self, job_id: ID) -> Tuple[URL, str, ID]:
        """
        Helper function for extracting uploaded image URL and ID
        :param job_id: upload job ID
        :return: tuple consisting of uploaded image URL, short image URL and ID
        """
        response = requests.get(
            self._url(FW_UPLOAD_JOB, id=job_id),
            headers=self._headers())
        response.raise_for_status()
        image_id = response.json()['firmware_image_id']
        response = requests.get(
            self._url(FW_IMAGE, id=image_id),
            headers=self._headers())
        response.raise_for_status()
        url = response.json()['datafile']
        short_url = response.json()['short_datafile']
        return url, short_url, image_id

    def _delete_upload_job(self, job_id: ID):
        """
        Helper function for deleting a firmware image upload job
        :param job_id: upload job ID
        """
        response = requests.delete(
            self._url(FW_UPLOAD_JOB, id=job_id),
            headers=self._headers()
        )
        response.raise_for_status()
        LOG.debug('FW upload job %s deleted', job_id)

    def _create_upload_job(self, fw_name: str) -> ID:
        """
        Helper function for creating a firmware image upload job
        :param fw_name: fw name as appears on the portal
        :return: upload job ID
        """
        response = requests.post(
            self._url(FW_UPLOAD_JOBS),
            headers=self._headers(),
            json={'name': fw_name}
        )
        response.raise_for_status()
        response_data = response.json()
        job_id = response_data['id']
        LOG.debug('FW upload job created %s', job_id)
        return job_id

    def fw_delete(self, image_id: ID):
        """
        Delete candidate image from Pelion portal
        :param image_id: image ID as appears on the portal
        """
        response = requests.delete(
            self._url(FW_IMAGE, id=image_id),
            headers=self._headers()
        )
        response.raise_for_status()
        LOG.info('Deleted FW image %s', image_id)

    def manifest_upload(self, name: str, manifest: Path) -> ID:
        """
        Upload manifest file to Pelion service
        :param name: manifest name as will appear on Pelion portal
        :param manifest: manifest file
        :return: manifest ID as reported by portal
        """
        try:
            with manifest.open('rb') as fh:
                response = requests.post(
                    self._url(FW_MANIFESTS),
                    headers=self._headers(),
                    files={
                        'datafile': (manifest.name, fh),
                    },
                    data={
                        'name': name
                    }
                )
                response.raise_for_status()
                manifest_id = response.json()['id']
                LOG.info('Uploaded manifest ID: %s', manifest_id)
                return manifest_id
        except requests.HTTPError:
            LOG.error('Failed to upload manifest')
            raise

    def manifest_delete(self, manifest_id: ID):
        """
        Delete manifest file from Pelion portal
        :param manifest_id: manifest ID to be deleted
        """
        response = requests.delete(
            self._url(FW_MANIFEST, id=manifest_id),
            headers=self._headers()
        )
        response.raise_for_status()
        LOG.info('Deleted manifest ID: %s', manifest_id)

    def campaign_create(
            self,
            name: str,
            manifest_id: ID,
            device_filter: str
    ) -> ID:
        """
        Create update campaign om Pelion portal

        :param name: campaign name as will appear on Pelion portal
        :param manifest_id: manifest ID as
        :param device_filter: device filter query
        :return: campaign ID as reported by portal
        """
        try:
            response = requests.post(
                self._url(FW_CAMPAIGNS),
                headers=self._headers(),
                json={
                    'campaign_strategy': 'one-shot',
                    'description': 'Development campaign',
                    'device_filter': device_filter,
                    'name': name,
                    'root_manifest_id': manifest_id
                }
            )
            response.raise_for_status()
            campaign_id = response.json()['id']
            LOG.info('Created Campaign ID: %s', campaign_id)
            return campaign_id
        except requests.HTTPError:
            LOG.error('Failed to create campaign')
            raise

    def campaign_delete(self, campaign_id: ID):
        """
        Delete inactive (stopped/draft) update campaign
        :param campaign_id: campaign ID
        """
        response = requests.delete(
            self._url(FW_CAMPAIGN, id=campaign_id),
            headers=self._headers()
        )
        response.raise_for_status()
        LOG.info('Deleted campaign %s', campaign_id)

    def campaign_stop(self, campaign_id: ID):
        """
        Stop update campaign
        :param campaign_id: campaign ID
        """
        try:
            # check campaign phase and skip if it not active
            curr_phase = self.campaign_get(campaign_id)['phase']
            if not self.campaign_is_active(curr_phase):
                return
            # send request to stop
            response = requests.post(
                self._url(FW_CAMPAIGN_STOP, id=campaign_id),
                headers=self._headers()
            )
            response.raise_for_status()
            curr_phase = self.campaign_get(campaign_id)['phase']
            # The campaign is stopping. wait a minute for it to finish
            retries = 60
            while curr_phase == 'stopping' and retries > 0:
                time.sleep(1)
                curr_phase = self.campaign_get(campaign_id)['phase']
                retries -= 1
            if retries == 0:
                LOG.debug('Stopping Campaign timed out')
            LOG.info('Stopped campaign %s', campaign_id)
        except requests.HTTPError as ex:
            # ignore error from stop campaign as it may already be stopped
            LOG.debug("Failed stopping campaign - %s", ex)

    def campaign_start(self, campaign_id: ID):
        """
        Start draft update campaign
        :param campaign_id: campaign ID
        """
        try:
            response = requests.post(
                self._url(FW_CAMPAIGN_START, id=campaign_id),
                headers=self._headers()
            )
            response.raise_for_status()

            time.sleep(1)

            campaign = self.campaign_get(campaign_id)
            while True:
                if campaign['phase'] == 'draft':
                    raise AssertionError(
                        'Campaign not started - check filter and campaign '
                        'state.\n'
                        'Reason: {}'.format(campaign['autostop_reason']))
                if campaign['phase'] == 'active':
                    break
                campaign = self.campaign_get(campaign_id)
        except requests.HTTPError:
            LOG.error('Failed to start campaign %s', campaign_id)
            raise
        LOG.info('Started Campaign ID: %s', campaign_id)

    def campaign_get(self, campaign_id: ID) -> dict:
        """
        Get update campaign current representation/state
        :param campaign_id:
        :return: Dictionary with current update campaign state
        """
        response = requests.get(
            self._url(FW_CAMPAIGN, id=campaign_id),
            headers=self._headers()
        )
        response.raise_for_status()
        return response.json()

    def campaign_statistics(self, campaign_id: ID) -> List[dict]:
        """
        Get campaign statistics

        :param campaign_id: campaign ID
        :return: List of statistics for a campaign
        """
        try:
            response = requests.get(
                self._url(FW_CAMPAIGN_STATISTICS, id=campaign_id),
                headers=self._headers()
            )
            response.raise_for_status()
            return response.json()['data']
        except requests.HTTPError:
            pass
        return []

    def campaign_device_metadata(self, campaign_id: ID) -> List[dict]:
        """
        Get metadata for devices participating in update campaign

        Note: this function and assumes small number of devcises participating
        in update campaign (as part of developer flow). Thus it does not
        handles pagination
        :param campaign_id: campaign ID
        :return: List of device metadata dictionaries for devices participating
        in update campaign
        """
        response = requests.get(
            self._url(FW_CAMPAIGN_DEV_METADATA, id=campaign_id),
            headers=self._headers()
        )
        response.raise_for_status()
        return response.json()['data']

    @staticmethod
    def campaign_is_active(phase: Phase) -> bool:
        """
        Helper function for understanding if update campaign is in active phase
        :param phase: current update campaign phase
        :return: True if update campaign phase is starting or active
        """
        return phase in CAMPAIGN_ACTIVE_PHASES
