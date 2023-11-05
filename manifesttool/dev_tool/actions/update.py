# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
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
"""Manifest-dev-tool update command."""
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import requests

from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.actions.create import load_cfg_and_get_fw_ver
from manifesttool.dev_tool.actions.create import (
    register_parser as register_create_parser,
)
from manifesttool.dev_tool.actions.create import create_dev_manifest
from manifesttool.dev_tool.izuma import izuma
from manifesttool.common.common_helpers import get_non_negative_int_argument
from manifesttool.mtool.asn1 import ManifestAsnCodecBase

logger = logging.getLogger("manifest-dev-tool-update")

# The update API has a maximum name length of 128, but this is not queryable.
MAX_NAME_LEN = 128


def register_parser(parser: argparse.ArgumentParser, schema_version: str):
    """Register the parser."""
    register_create_parser(parser, schema_version, True)

    pdm_group = parser.add_argument_group(
        "optional arguments (Tool's campaign management)"
    )

    pdm_group.add_argument(
        "-i",
        "--device-id",
        help="Device ID for targeting a specific device in "
        "update campaign filter.",
    )

    pdm_group.add_argument(
        "-s",
        "--start-campaign",
        action="store_true",
        help="Create and start update campaign automatically.",
    )
    pdm_group.add_argument(
        "-w",
        "--wait-for-completion",
        dest="wait",
        action="store_true",
        help="Create and start update campaign automatically, "
        "wait for it to finish, and clean up created resources.",
    )
    pdm_group.add_argument(
        "-t",
        "--timeout",
        type=get_non_negative_int_argument,
        help="Wait timeout in seconds. " "[Default: 0 - wait-forever]",
        default=0,
    )
    pdm_group.add_argument(
        "-n",
        "--no-cleanup",
        action="store_true",
        help="Skip cleaning up created resources. "
        "Only relevant if --wait-for-completion was provided.",
    )


def _manage_campaign(
    api: izuma.IzumaServiceApi,
    campaign_id: izuma.ID,
    end_time: int,
    do_wait: bool,
):
    starting = True
    old_state = ""
    try:
        api.campaign_start(campaign_id)
    except requests.HTTPError:
        logger.error("Failed to start campaign %s", campaign_id)
        raise
    try:
        while end_time == 0 or time.time() < end_time:
            try:
                curr_campaign = api.campaign_get(campaign_id)
            except requests.ConnectionError as ex:
                logger.debug("Connection error %s", ex)
                time.sleep(3)
                continue
            curr_state = curr_campaign["state"]
            curr_phase = curr_campaign["phase"]
            if starting:
                if api.campaign_is_not_started(curr_phase):
                    raise AssertionError(
                        "Campaign not started - check filter and campaign "
                        "state.\n"
                        "Reason: {}".format(curr_campaign["autostop_reason"])
                    )
                if api.campaign_is_active(curr_phase):
                    logger.info("Started Campaign ID: %s", campaign_id)
                    starting = False
                    if not do_wait:
                        return
            else:
                if not api.campaign_is_active(curr_phase):
                    logger.info(
                        "Campaign is finished in state: %s", curr_state
                    )
                    return
            if old_state != curr_state:
                logger.info("Campaign state: %s", curr_state)
                old_state = curr_state
            time.sleep(3)
        logger.error("Campaign timed out")
        raise AssertionError("Campaign timed out")
    except requests.HTTPError:
        logger.error("Failed to retrieve campaign state")
        raise


def _print_summary(summary: dict, summary_reasons: dict):
    logger.info("----------------------------")
    logger.info("    Campaign Summary ")
    logger.info("----------------------------")
    logger.info(
        " Successfully updated:   %d",
        summary.get("success") if summary.get("success") else 0,
    )
    logger.info(
        " Failed to update:       %d",
        summary.get("fail") if summary.get("fail") else 0,
    )
    logger.info(
        " Skipped:                %d",
        summary.get("skipped") if summary.get("skipped") else 0,
    )
    logger.info(
        " Pending:                %d",
        summary.get("info") if summary.get("info") else 0,
    )
    logger.info(" Total in this campaign: %d", sum(summary.values()))
    if summary_reasons.get("fail"):
        logger.warning("Reasons for failed updates:")
        for reasons in summary_reasons["fail"]:
            if reasons.get("description"):
                logger.warning(" %s", reasons.get("description"))
    if summary_reasons.get("skipped"):
        logger.warning("Reasons for skipped updates:")
        for reasons in summary_reasons["skipped"]:
            if reasons.get("description"):
                logger.warning(" %s", reasons.get("description"))


def _finalize(
    api: izuma.IzumaServiceApi,
    do_cleanup: bool,
    campaign_id: izuma.ID,
    manifest_id: izuma.ID,
    fw_image_id: izuma.ID,
    manifest_path: Path,
):
    summary = {}
    summary_reasons = {}
    failed_devices = []
    try:
        if campaign_id:
            # stop the campaign if it's still active
            api.campaign_stop(campaign_id)
            # get summary, failed devices and reasons
            statistics = api.campaign_statistics(campaign_id)
            summary = {s["id"]: s["count"] for s in statistics}
            if summary.get("fail") and summary.get("fail") > 0:
                devices_state = api.campaign_device_metadata(campaign_id)
                failed_devices = [
                    d["device_id"]
                    for d in devices_state
                    if d["deployment_state"] != "deployed"
                ]
                summary_reasons["fail"] = api.campaign_statistic_events(
                    campaign_id, "fail"
                )
            if summary.get("skipped") and summary.get("skipped") > 0:
                summary_reasons["skipped"] = api.campaign_statistic_events(
                    campaign_id, "skipped"
                )
        if do_cleanup:
            logger.info("Cleaning up resources...")
            if campaign_id:
                api.campaign_delete(campaign_id)
            if manifest_id:
                api.manifest_delete(manifest_id)
            if fw_image_id:
                api.fw_delete(fw_image_id)
            if manifest_path and manifest_path.is_file():
                manifest_path.unlink()
    except requests.HTTPError as ex:
        logger.error("Failed to finalize update campaign")
        logger.debug("Exception %s", ex, exc_info=True)

    # print campaign summary
    if summary:
        _print_summary(summary, summary_reasons)
        if failed_devices:
            # assert if not all devices were updated
            raise AssertionError(
                "Failed to update {} devices: {}".format(
                    len(failed_devices), ", ".join(failed_devices)
                )
            )


def update(
    payload_path: Path,
    dev_cfg: dict,
    manifest_version: Type[ManifestAsnCodecBase],
    priority: int,
    vendor_data: Path,
    device_id: str,
    do_wait: bool,
    do_start: bool,
    end_time: int,
    do_cleanup: bool,
    service_config: Path,
    fw_version: str,
    sign_image: bool,
    component: str,
    short_url: bool,
    encrypt_payload: bool,
    combined_package: bool,
):
    """Update command."""
    api = izuma.IzumaServiceApi(service_config)
    manifest_path = None
    fw_image_id = None
    manifest_id = None
    campaign_id = None
    encrypted_digest = None
    encrypted_size = None
    try:
        timestamp = time.strftime("%Y_%m_%d-%H_%M_%S")
        logger.info("Uploading FW image %s", payload_path.as_posix())

        fw_meta = api.fw_upload(
            fw_name="{}-{}".format(timestamp, payload_path.name),
            image=payload_path,
            encrypt=encrypt_payload,
        )

        fw_image_id = fw_meta["id"]
        payload_url = fw_meta["short_datafile" if short_url else "datafile"]

        if encrypt_payload:
            if (
                fw_meta.get("datafile_encryption", False)
                and fw_meta.get("encrypted_datafile_checksum", False)
                and fw_meta.get("encrypted_datafile_size", False)
            ):
                encrypted_digest = fw_meta["encrypted_datafile_checksum"]
                encrypted_size = fw_meta["encrypted_datafile_size"]
            else:
                raise AssertionError(
                    "Request to encrypt payload failed! "
                    "Device Management doesn't support this feature."
                )

        manifest_data = create_dev_manifest(
            dev_cfg=dev_cfg,
            manifest_version=manifest_version,
            vendor_data_path=vendor_data,
            payload_path=payload_path,
            payload_url=payload_url,
            encrypted_digest=encrypted_digest,
            encrypted_size=encrypted_size,
            priority=priority,
            fw_version=fw_version,
            sign_image=sign_image,
            component=component,
            combined_package=combined_package,
        )

        manifest_name = "manifest-{timestamp}-{filename}".format(
            filename=payload_path.name, timestamp=timestamp
        )
        manifest_path = payload_path.parent / manifest_name

        manifest_path.write_bytes(manifest_data)
        manifest_id = api.manifest_upload(
            name=manifest_name, manifest=manifest_path
        )

        campaign_name = "campaign-{timestamp}-{filename}".format(
            filename=payload_path.name, timestamp=timestamp
        )

        filters = [
            "device_class__eq={}".format(dev_cfg["class-id"]),
            "vendor_id__eq={}".format(dev_cfg["vendor-id"]),
        ]
        if device_id:
            filters.append("id__eq={}".format(device_id))
        filters_query = "&".join(filters)
        campaign_id = api.campaign_create(
            name=campaign_name,
            manifest_id=manifest_id,
            device_filter=filters_query,
        )

        if do_start:
            _manage_campaign(api, campaign_id, end_time, do_wait)

    except requests.HTTPError as ex:
        # log additional service info
        srv_message = ex.response.json().get("message", None)
        if srv_message:
            logger.error(srv_message)
        raise
    except KeyboardInterrupt:
        logger.error("Aborted by user...")
    finally:
        if do_wait:
            _finalize(
                api,
                do_cleanup,
                campaign_id,
                manifest_id,
                fw_image_id,
                manifest_path,
            )


def entry_point(args, manifest_version: Type[ManifestAsnCodecBase]):
    """Entry point of the update command."""
    dev_cfg, fw_version = load_cfg_and_get_fw_ver(args, manifest_version)

    encrypt_payload = hasattr(args, "encrypt_payload") and args.encrypt_payload

    update(
        payload_path=args.payload_path,
        dev_cfg=dev_cfg,
        manifest_version=manifest_version,
        priority=args.priority,
        vendor_data=args.vendor_data,
        device_id=args.device_id,
        do_start=args.start_campaign or args.wait,
        do_wait=args.wait,
        end_time=time.time() + args.timeout if args.timeout > 0 else 0,
        do_cleanup=not args.no_cleanup,
        service_config=args.cache_dir / defaults.CLOUD_CFG,
        fw_version=fw_version,
        sign_image=getattr(args, "sign_image", False),
        component=getattr(args, "component_name", None),
        short_url=hasattr(args, "use_short_url") and args.use_short_url,
        encrypt_payload=encrypt_payload,
        combined_package=getattr(args, "combined_image", False),
    )
