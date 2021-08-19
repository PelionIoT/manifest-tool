# ----------------------------------------------------------------------------
# Copyright 2021 Pelion
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
import datetime
import logging
import re
from pathlib import Path

import requests
from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.pelion import pelion

logger = logging.getLogger('manifest-dev-tool-cleaner')

def get_cutoff_time(value: str) -> datetime:
    pattern = '^' + r'(\d+)([HD])' + '$'
    match = re.match(pattern, value.upper())
    if not match:
        raise argparse.ArgumentTypeError(
            '"{}" is not in expected format. '
            '<Number><H|D>'.format(value))
    if match.group(2) == 'H':
        delta = datetime.timedelta(hours=int(match.group(1)))
    else:
        delta = datetime.timedelta(days=int(match.group(1)))
    return datetime.datetime.utcnow() - delta

def register_parser(parser: argparse.ArgumentParser):

    parser.add_argument(
        '--delete',
        help='List of objects to be deleted. Default: Delete all objects.',
        choices=['devices', 'fw-images', 'manifests', 'campaigns'],
        default=['devices', 'fw-images', 'manifests', 'campaigns'],
        nargs='*'
    )

    parser.add_argument(
        '--delete-active',
        help='Also delete active objects. Default: False',
        action='store_true',
        default=False
    )

    parser.add_argument(
        '--older-than',
        type=get_cutoff_time,
        default=get_cutoff_time('7D'),
        help='Delete objects older than specified time. '
             'Format: <Number><H(ours)|D(ays)>. '
             'Default: 7D'
    )

    parser.add_argument(
        '-q', '--quiet',
        help='Don\'t prompt for confirmation.',
        action='store_true',
        default=False
    )

    parser.add_argument(
        '--cache-dir',
        help='Tool\'s cache directory. '
             'Must match the directory used by the "init" command.',
        type=Path,
        default=defaults.BASE_PATH
    )
    parser.add_argument(
        '-h',
        '--help',
        action='help',
        help='Show this help message and exit.'
    )

def filter_out_active_objects(
    api: pelion.PelionServiceApi,
    campaigns: list,
    manifests: list,
    fw_images: list,
    devices: list
) -> tuple:
    # If the user request to delete only inactive objects,
    #  need to filter out devices, fw images and manifests that
    #  take part in active campaigns.

    active_campaigns = []
    inactive_campaigns = []
    active_devices = []
    active_manifests_ids = []
    for campaign in campaigns:
        if api.campaign_is_active(campaign['phase']):
            active_campaigns.append(campaign)
            campaign_devices = \
                api.get_devices(campaign['device_filter'])
            active_devices.extend(campaign_devices)
            active_manifests_ids.append(campaign['root_manifest_id'])
        else:
            inactive_campaigns.append(campaign)

    # build list of unique active_devices_ids
    active_devices_ids = []
    for device in active_devices:
        if device['id'] not in active_devices_ids:
            active_devices_ids.append(device['id'])

    # filter out active_devices_ids from devices
    inactive_devices = \
        [d for d in devices if d['id'] not in active_devices_ids]

    # split manifests list
    active_manifests = []
    inactive_manifests = []
    for manifest in manifests:
        if manifest['id'] in active_manifests_ids:
            active_manifests.append(manifest)
        else:
            inactive_manifests.append(manifest)

    active_fw_images_ids = []
    for fw_image in fw_images:
        for manifest in active_manifests:
            # check if fw_image url equals delivered_payload_url
            if manifest['delivered_payload_url'] in \
                    (fw_image['datafile'], fw_image['short_datafile']):
                active_fw_images_ids.append(fw_image['id'])
                break

    # filter out active_fw_image_ids from fw_images
    inactive_fw_images = \
        [f for f in fw_images if f['id'] not in active_fw_images_ids]

    return (
        inactive_campaigns,
        inactive_manifests,
        inactive_fw_images,
        inactive_devices
    )

def get_objects_to_delete(
    args: dict,
    api: pelion.PelionServiceApi
) -> list:

    older_than_filter = 'created_at__lte={}Z'.format(
        args.older_than.isoformat()
    )

    # filter only development devices
    devices_filter = 'device_execution_mode__eq=1&' + older_than_filter
    if not args.delete_active:
        # filter out registered devices
        devices_filter = devices_filter + '&state__neq=registered'
    devices = api.get_devices(devices_filter)

    fw_images = api.get_fw_images(older_than_filter)
    manifests = api.get_manifests(older_than_filter)
    campaigns = api.get_campaigns(older_than_filter)

    if not args.delete_active:
        # filter out active objects
        campaigns, manifests, fw_images, devices = \
            filter_out_active_objects(
                api, campaigns, manifests, fw_images, devices
            )

    objects = {}
    if 'devices' in args.delete and len(devices) > 0:
        objects['device'] = devices
    if 'fw-images' in args.delete and len(fw_images) > 0:
        objects['firmware-image'] = fw_images
    if 'manifests' in args.delete and len(manifests) > 0:
        objects['firmware-manifest'] = manifests
    if 'campaigns' in args.delete and len(campaigns) > 0:
        objects['update-campaign'] = campaigns

    return objects

def _stop_campaigns(
    campaigns: list,
    api: pelion.PelionServiceApi
):
    active_campaigns = [
        c for c in campaigns if api.campaign_is_active(c['phase'])
    ]
    if len(active_campaigns) == 0:
        return

    logger.debug('Stopping %d active campaigns', len(active_campaigns))
    for campaign in active_campaigns:
        if api.campaign_is_active(campaign['phase']):
            api.campaign_stop(campaign['id'], timeout=3)

def clean_objects(
    args: dict,
    api: pelion.PelionServiceApi
):

    objects_dict = get_objects_to_delete(args, api)
    if len(objects_dict) == 0:
        logger.info('Nothing to delete')
        return

    cleaner = {
        'device': api.device_delete,
        'firmware-image': api.fw_delete,
        'firmware-manifest': api.manifest_delete,
        'update-campaign': api.campaign_delete,
    }

    # print what is going to be done
    for objects in objects_dict.values():
        logger.info('Will delete %d %ss', len(objects), objects[0]['object'])
    if not args.delete_active:
        logger.info('Will skip registered devices, active campaigns '
                    'and objects that participate in active campaigns')

    if not args.quiet:
        user_confirm = input('Do you want to proceed? (Yes/No) ').lower()
        if user_confirm not in ('y', 'yes'):
            return

    # first stop active campaigns
    if 'update-campaign' in objects_dict:
        _stop_campaigns(objects_dict['update-campaign'], api)

    failed_objs = []
    for objects in objects_dict.values():
        for obj in objects:
            try:
                cleaner[obj['object']](obj['id'])
            except requests.HTTPError:
                # add to failed_objs and continue
                failed_objs.append(obj)

    for obj in failed_objs:
        logger.error(
            'Failed to delete %s %s', obj['object'], obj['id']
        )


def entry_point(
        args
):
    api = pelion.PelionServiceApi(args.cache_dir / defaults.CLOUD_CFG)

    try:
        clean_objects(args, api)
    except KeyboardInterrupt:
        pass
