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
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import urllib3
import yaml
from mbed_cloud.exceptions import CloudApiException
from mbed_cloud.update import UpdateAPI

from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.actions.create import bump_minor
from manifesttool.dev_tool.actions.create import create_dev_manifest
from manifesttool.mtool.actions import existing_file_path_arg_factory
from manifesttool.mtool.actions import non_negative_int_arg_factory
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.asn1 import ManifestAsnCodecBase

logger = logging.getLogger('manifest-dev-tool-update')

# The update API has a maximum name length of 128, but this is not queryable.
MAX_NAME_LEN = 128

STOP_STATES = {
    'autostopped',
    'conflict',
    'expired',
    'manifestremoved',
    'quotaallocationfailed',
    'userstopped'
}


def register_parser(parser: argparse.ArgumentParser, schema_version: str):

    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')

    required.add_argument(
        '-p', '--payload-path',
        help='Payload local path - for digest calculation.',
        type=existing_file_path_arg_factory,
        required=True
    )

    if schema_version == 'v1':
        optional.add_argument(
            '-v', '--fw-version',
            type=non_negative_int_arg_factory,
            help='FW version to be set in manifest. '
                 '[Default: current timestamp]',
            default=int(time.time())
        )
    else:
        optional.add_argument(
            '-v', '--fw-version',
            type=semantic_version_arg_factory,
            help='FW version to be set in manifest in Semantic '
                 'Versioning Specification format.'
        )
        optional.add_argument(
            '--component-name',
            default='MAIN',
            metavar='NAME',
            help='Component name to be udpated. Must correspond to existing '
                 'components name on targeted devices'
        )
        optional.add_argument(
            '-m', '--sign-image',
            action='store_true',
            help='Sign image. Should be used when bootloader on a device '
                 'expects signed FW image.'
        )

    optional.add_argument(
        '-r', '--priority',
        type=non_negative_int_arg_factory,
        help='Update priority >=0. [Default: 0]',
        metavar='INT',
        default=0
    )

    optional.add_argument(
        '-d', '--vendor-data',
        help='Vendor custom data - to be passed to a device.',
        type=existing_file_path_arg_factory
    )

    pdm_group = parser.add_argument_group('optional PDM portal arguments')

    pdm_group.add_argument(
        '-i', '--device-id',
        help='Device ID for for targeting a specific device in '
             'update campaign filter.'
    )

    pdm_group.add_argument(
        '-s', '--start-campaign',
        action='store_true',
        help='Start campaign automatically.'
    )
    pdm_group.add_argument(
        '-w', '--wait-for-completion',
        dest='wait',
        action='store_true',
        help='Wait for campaign to finish and cleanup created resources.'
    )
    pdm_group.add_argument(
        '-t', '--timeout',
        type=non_negative_int_arg_factory,
        help='Timeout in seconds. '
             'Only relevant in case --wait-for-completion was provided. '
             '[Default: 360sec]',
        default=360
    )
    pdm_group.add_argument(
        '-n', '--no-cleanup',
        action='store_true',
        help='Skip created service resources cleanup. '
             'Only relevant in case --wait-for-completion was provided.'
    )

    optional.add_argument(
        '--cache-dir',
        help='Tool cache directory. '
             'Must match the directory used by "init" command',
        type=Path,
        default=defaults.BASE_PATH
    )

    optional.add_argument(
        '-h',
        '--help',
        action='help',
        help='show this help message and exit'
    )

def _upload_manifest(api, manifest_name, manifest_path):
    try:
        manifest = api.add_firmware_manifest(
            name=manifest_name,
            datafile=manifest_path.as_posix())
    except CloudApiException:
        logger.error('Manifest upload failed')
        raise

    logger.info('Uploaded Manifest ID: %s', manifest.id)
    return manifest


def _create_campaign(
        api,
        campaign_name,
        manifest_cloud,
        vendor_id,
        class_id,
        device_id
):
    try:
        device_filter = {
            'device_class': {'$eq': class_id},
            'vendor_id': {'$eq': vendor_id},
        }
        if device_id:
            device_filter['id'] = {'$eq': device_id}
        campaign = api.add_campaign(
            name=campaign_name,
            manifest_id=manifest_cloud.id,
            device_filter=device_filter,
        )
    except CloudApiException:
        logger.error('Campaign creation failed')
        raise
    logger.info('Campaign successfully created ID: %s', campaign.id)
    logger.info('Current state: %s', campaign.state)
    logger.debug('Filter result: %s', campaign.device_filter)
    return campaign


def _start_campaign(api, campaign_cloud):
    try:
        api.start_campaign(campaign_cloud)
    except CloudApiException:
        logger.error('Starting campaign failed')
        raise
    logger.info('Started Campaign ID: %s', campaign_cloud.id)


def _wait(api, existing_campaign, timeout):
    try:
        old_state = api.get_campaign(existing_campaign.id).state
        logger.info("Campaign state: %s", old_state)
        current_time = time.time()
        while time.time() < current_time + timeout:
            campaign = api.get_campaign(existing_campaign.id)
            if old_state != campaign.state:
                logger.info("Campaign state: %s", campaign.state)
                old_state = campaign.state
            if campaign.state in STOP_STATES:
                logger.info(
                    "Campaign is finished in state: %s", campaign.state)
                return
            time.sleep(1)
        logger.error('Campaign timed out')
        raise AssertionError('Campaign timed out')
    except KeyboardInterrupt:
        logger.error('Aborted by user...')
        return
    except CloudApiException:
        logger.error('Failed to retrieve campaign status')
        raise


def update(
        payload_path: Path,
        dev_cfg: dict,
        manifest_version: Type[ManifestAsnCodecBase],
        priority: int,
        vendor_data: Path,
        device_id: str,
        do_wait: bool,
        do_start: bool,
        timeout: int,
        skip_cleanup: bool,
        service_config: Path,
        fw_version: str,
        sign_image: bool,
        component: str
):
    config = None
    if service_config.is_file():
        with service_config.open('rt') as fh:
            config = yaml.safe_load(fh)

    api = UpdateAPI(config)
    manifest_path = None
    payload_cloud = None
    manifest_cloud = None
    campaign_cloud = None
    try:
        timestamp = time.strftime('%Y_%m_%d-%H_%M_%S')
        payload_cloud = _upload_payload(
            api,
            payload_name='{timestamp}-{filename}'.format(
                filename=payload_path.name,
                timestamp=timestamp),
            payload_path=payload_path
        )

        manifest_data = create_dev_manifest(
            dev_cfg=dev_cfg,
            manifest_version=manifest_version,
            vendor_data_path=vendor_data,
            payload_path=payload_path,
            payload_url=payload_cloud.url,
            priority=priority,
            fw_version=fw_version,
            sign_image=sign_image,
            component=component
        )

        manifest_name = 'manifest-{timestamp}-{filename}'.format(
            filename=payload_path.name,
            timestamp=timestamp)
        manifest_path = payload_path.parent / manifest_name

        manifest_path.write_bytes(manifest_data)

        manifest_cloud = _upload_manifest(api, manifest_name, manifest_path)

        campaign_name = 'campaign-{timestamp}-{filename}'.format(
            filename=payload_path.name,
            timestamp=timestamp)

        campaign_cloud = _create_campaign(
            api,
            campaign_name,
            manifest_cloud,
            dev_cfg['vendor-id'],
            dev_cfg['class-id'],
            device_id
        )

        if do_start:
            _start_campaign(api, campaign_cloud)

        if do_wait:
            _wait(api, campaign_cloud, timeout)

    finally:
        if not skip_cleanup and do_wait:
            try:
                logger.info('Cleaning up resources.')
                if campaign_cloud:
                    logger.info('Deleting campaign %s', campaign_cloud.id)
                    api.delete_campaign(campaign_cloud.id)
                if manifest_cloud:
                    logger.info('Deleting FW manifest %s', manifest_cloud.id)
                    api.delete_firmware_manifest(manifest_cloud.id)
                if payload_cloud:
                    logger.info('Deleting FW image %s', payload_cloud.id)
                    api.delete_firmware_image(payload_cloud.id)
                if manifest_path and manifest_path.is_file():
                    manifest_path.unlink()
            except CloudApiException:
                logger.error('Failed to cleanup resources')


def _upload_payload(api, payload_name, payload_path):
    try:
        logger.info('Uploading FW payload %s', payload_path.as_posix())
        payload = api.add_firmware_image(
            name=payload_name,
            datafile=payload_path.as_posix()
        )
    except (CloudApiException, urllib3.exceptions.MaxRetryError):
        logger.error('Payload upload failed')
        logger.error('Failed to establish connection to API-GW')
        logger.error('Check API server URL "%s"', api.config["host"])
        raise
    logger.info('Uploaded FW payload %s', payload.url)
    return payload


def entry_point(
        args,
        manifest_version: Type[ManifestAsnCodecBase]
):

    cache_dir = args.cache_dir

    if not cache_dir.is_dir():
        raise AssertionError('Tool cache directory is missing. '
                             'Execute "init" command to create it.')

    with (cache_dir / defaults.DEV_CFG).open('rt') as fh:
        dev_cfg = yaml.safe_load(fh)

    cache_fw_version_file = cache_dir / defaults.UPDATE_VERSION
    fw_version = args.fw_version
    if 'v1' not in manifest_version.get_name():
        if not fw_version:
            fw_version = cache_fw_version_file.read_text()
            fw_version = bump_minor(fw_version)
        cache_fw_version_file.write_text(fw_version)
        logger.info('FW version: %s', fw_version)
    else:
        assert fw_version is not None
        logger.info('FW version: %d', fw_version)

    update(
        payload_path=args.payload_path,
        dev_cfg=dev_cfg,
        manifest_version=manifest_version,
        priority=args.priority,
        vendor_data=args.vendor_data,
        device_id=args.device_id,
        do_start=args.start_campaign or args.wait,
        do_wait=args.wait,
        timeout=args.timeout,
        skip_cleanup=args.no_cleanup,
        service_config=cache_dir / defaults.CLOUD_CFG,
        fw_version=fw_version,
        sign_image=getattr(args, 'sign_image', False),
        component=getattr(args, 'component_name', None)
    )
