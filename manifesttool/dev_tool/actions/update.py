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
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import yaml
from requests import HTTPError

from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.actions.create import bump_minor
from manifesttool.dev_tool.actions.create \
    import register_parser as register_create_parser
from manifesttool.dev_tool.actions.create import create_dev_manifest
from manifesttool.dev_tool.pelion import pelion
from manifesttool.mtool.actions import non_negative_int_arg_factory
from manifesttool.mtool.asn1 import ManifestAsnCodecBase

logger = logging.getLogger('manifest-dev-tool-update')

# The update API has a maximum name length of 128, but this is not queryable.
MAX_NAME_LEN = 128


def register_parser(parser: argparse.ArgumentParser, schema_version: str):

    register_create_parser(parser, schema_version, True)

    pdm_group = parser.add_argument_group(
        'optional arguments (Tool\'s campaign management)'
    )

    pdm_group.add_argument(
        '-i', '--device-id',
        help='Device ID for targeting a specific device in '
             'update campaign filter.'
    )

    pdm_group.add_argument(
        '-s', '--start-campaign',
        action='store_true',
        help='Create and start update campaign automatically.'
    )
    pdm_group.add_argument(
        '-w', '--wait-for-completion',
        dest='wait',
        action='store_true',
        help='Create and start update campaign automatically, '
             'wait for it to finish, and clean up created resources.'
    )
    pdm_group.add_argument(
        '-t', '--timeout',
        type=non_negative_int_arg_factory,
        help='Wait timeout in seconds. '
             'Only relevant if --wait-for-completion was provided. '
             '[Default: 0 - wait-forever]',
        default=0
    )
    pdm_group.add_argument(
        '-n', '--no-cleanup',
        action='store_true',
        help='Skip cleaning up created resources. '
             'Only relevant if --wait-for-completion was provided.'
    )


def _wait(api: pelion.UpdateServiceApi, campaign_id: pelion.ID, timeout):
    try:
        old_state = api.campaign_get(campaign_id)['state']
        logger.info("Campaign state: %s", old_state)
        current_time = time.time()
        while timeout == 0 or time.time() < current_time + timeout:
            curr_campaign = api.campaign_get(campaign_id)
            curr_state = curr_campaign['state']
            curr_phase = curr_campaign['phase']
            if old_state != curr_state:
                logger.info("Campaign state: %s", curr_state)
                old_state = curr_state
            if not api.campaign_is_active(curr_phase):
                logger.info(
                    "Campaign is finished in state: %s", curr_state)
                return
            time.sleep(1)
        logger.error('Campaign timed out')
        raise AssertionError('Campaign timed out')
    except HTTPError:
        logger.error('Failed to retrieve campaign state')
        raise

def _print_summary(summary: dict):
    logger.info("----------------------------")
    logger.info("    Campaign Summary ")
    logger.info("----------------------------")
    logger.info(" Successfully updated:   %d",
                summary.get('success') if summary.get('success') else 0)
    logger.info(" Failed to update:       %d",
                summary.get('fail') if summary.get('fail') else 0)
    logger.info(" Skipped:                %d",
                summary.get('skipped') if summary.get('skipped') else 0)
    logger.info(" Pending:                %d",
                summary.get('info') if summary.get('info') else 0)
    logger.info(" Total in this campaign: %d", sum(summary.values()))


def _finalize(api: pelion.UpdateServiceApi,
              do_cleanup: bool,
              campaign_id: pelion.ID,
              manifest_id: pelion.ID,
              fw_image_id: pelion.ID,
              manifest_path: Path):
    summary = []
    failed_devices = []
    try:
        if campaign_id:
            # stop the campaign if it's still active
            api.campaign_stop(campaign_id)
            # get summary and failed devices
            statistics = api.campaign_statistics(campaign_id)
            summary = {s['id']: s['count'] for s in statistics}
            if summary.get('fail') and summary.get('fail') > 0:
                devices_state = api.campaign_device_metadata(campaign_id)
                failed_devices = [d['device_id'] for d in devices_state
                                  if d['deployment_state'] != 'deployed']
        if do_cleanup:
            logger.info('Cleaning up resources...')
            if campaign_id:
                api.campaign_delete(campaign_id)
            if manifest_id:
                api.manifest_delete(manifest_id)
            if fw_image_id:
                api.fw_delete(fw_image_id)
            if manifest_path and manifest_path.is_file():
                manifest_path.unlink()
    except HTTPError as ex:
        logger.error('Failed to finalize update campaign')
        logger.debug('Exception %s', ex, exc_info=True)

    # print campaign summary
    if summary:
        _print_summary(summary)
        if failed_devices:
            # assert if not all devices were updated
            raise AssertionError(
                'Failed to update {} devices: {}'.format(
                    len(failed_devices), ', '.join(failed_devices)))


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
        do_cleanup: bool,
        service_config: Path,
        fw_version: str,
        sign_image: bool,
        component: str,
        short_url: bool
):
    config = load_service_config(service_config)

    api = pelion.UpdateServiceApi(
        host=config['host'], api_key=config['api_key'])
    manifest_path = None
    fw_image_id = None
    manifest_id = None
    campaign_id = None
    try:
        timestamp = time.strftime('%Y_%m_%d-%H_%M_%S')
        logger.info('Uploading FW image %s', payload_path.as_posix())

        fw_image_url, short_image_url, fw_image_id = api.fw_upload(
            fw_name='{timestamp}-{filename}'.format(
                filename=payload_path.name,
                timestamp=timestamp),
            image=payload_path
        )

        manifest_data = create_dev_manifest(
            dev_cfg=dev_cfg,
            manifest_version=manifest_version,
            vendor_data_path=vendor_data,
            payload_path=payload_path,
            payload_url=short_image_url if short_url else fw_image_url,
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
        manifest_id = api.manifest_upload(
            name=manifest_name,
            manifest=manifest_path
        )

        campaign_name = 'campaign-{timestamp}-{filename}'.format(
            filename=payload_path.name,
            timestamp=timestamp)

        filters = [
            'device_class__eq={}'.format(dev_cfg['class-id']),
            'vendor_id__eq={}'.format(dev_cfg['vendor-id']),
        ]
        if device_id:
            filters.append('id__eq={}'.format(device_id))
        filters_query = '&'.join(filters)
        campaign_id = api.campaign_create(
            name=campaign_name,
            manifest_id=manifest_id,
            device_filter=filters_query
        )

        if do_start:
            api.campaign_start(campaign_id)

        if do_wait:
            _wait(api, campaign_id, timeout)

    except KeyboardInterrupt:
        logger.error('Aborted by user...')
    finally:
        if do_wait:
            _finalize(api,
                      do_cleanup,
                      campaign_id,
                      manifest_id,
                      fw_image_id,
                      manifest_path)


def load_service_config(service_config):
    if service_config.is_file():
        with service_config.open('rt') as fh:
            config = yaml.safe_load(fh)
            if 'host' in config and 'api_key' in config:
                return config
    raise AssertionError('Pelion service configurations (URL and access key) '
                         'are not provided for assisted campaign '
                         'management')


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
    component_name = getattr(args, 'component_name', None)
    cache_fw_version_file = cache_dir / defaults.UPDATE_VERSION
    fw_version = args.fw_version
    if 'v1' not in manifest_version.get_name():
        if cache_fw_version_file.is_file():
            with cache_fw_version_file.open('rt') as fh:
                cached_versions = yaml.safe_load(fh)
        else:
            cached_versions = dict()
        if not fw_version:
            fw_version = cached_versions.get(component_name, '0.0.1')
            fw_version = bump_minor(fw_version)

        cached_versions[component_name] = fw_version

        with cache_fw_version_file.open('wt') as fh:
            yaml.dump(cached_versions, fh)
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
        do_cleanup=not args.no_cleanup,
        service_config=cache_dir / defaults.CLOUD_CFG,
        fw_version=fw_version,
        sign_image=getattr(args, 'sign_image', False),
        component=component_name,
        short_url=hasattr(args, 'use_short_url') and args.use_short_url
    )
