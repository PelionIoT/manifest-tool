# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
# Copyright 2023 Izuma Networks
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
"""Manifest-dev-tool create command."""
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import yaml

from manifesttool.dev_tool import defaults
from manifesttool.common.common_helpers import get_argument_path
from manifesttool.common.common_helpers import get_non_negative_int_argument
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.actions import semver_as_tuple_arg_factory
from manifesttool.mtool.actions.create import CreateAction
from manifesttool.mtool.asn1 import ManifestAsnCodecBase
from manifesttool.mtool.payload_format import PayloadFormat

logger = logging.getLogger("manifest-dev-tool-create")


def register_parser(
    parser: argparse.ArgumentParser,
    schema_version: str,
    is_update_parser: bool = False,
):
    """Register the parser."""
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")

    if not is_update_parser:
        required.add_argument(
            "-u",
            "--payload-url",
            help="Address from which the device downloads "
            "the candidate payload.",
            required=True,
        )

    required.add_argument(
        "-p",
        "--payload-path",
        help="Local path to the candidate payload file.",
        type=get_argument_path,
        required=True,
    )

    if not is_update_parser:
        required.add_argument(
            "-o",
            "--output",
            help="Output manifest filename.",
            type=argparse.FileType("wb"),
            required=True,
        )

    if schema_version == "v1":

        version_group = optional.add_mutually_exclusive_group()
        version_group.add_argument(
            "-v",
            "--fw-version",
            type=get_non_negative_int_argument,
            help="Version number (integer) of the candidate image. "
            "Default: current epoch time.",
            default=int(time.time()),
        )
        version_group.add_argument(
            "--fw-migrate-ver",
            type=semver_as_tuple_arg_factory,
            help="Version number of the candidate image in "
            "SemVer format. NOTE: Use to upgrade from "
            "v1 manifest schema to a later schema.",
        )

        optional.add_argument(
            "-r",
            "--priority",
            type=get_non_negative_int_argument,
            help="Set update priority >=0.",
        )
    else:  # v3
        if is_update_parser:
            optional.add_argument(
                "-e",
                "--encrypt-payload",
                action="store_true",
                help="Encrypt the payload the device downloads.",
            )
        else:
            optional.add_argument(
                "--encrypted-digest",
                type=str,
                help="Encrypted payload digest (32-byte HEX string)."
                " Use only if the candidate payload is encrypted.",
            )
            optional.add_argument(
                "--encrypted-size",
                type=get_non_negative_int_argument,
                help="Encrypted payload size."
                " Use only if the candidate payload is encrypted.",
            )
        optional.add_argument(
            "-v",
            "--fw-version",
            type=semantic_version_arg_factory,
            help="Version number of the candidate image in SemVer format. "
            "Min. 0.0.1, max 999.999.999. "
            "Must be bigger than the version currently "
            "in the device(s).",
        )
        optional.add_argument(
            "--component-name",
            default="MAIN",
            metavar="NAME",
            help="The name of the component to be updated. "
            "Must correspond to an existing component "
            "name on target devices. [Default: MAIN].",
        )
        if is_update_parser:
            optional.add_argument(
                "-u",
                "--use-short-url",
                action="store_true",
                help="Use a short candidate payload URL in the manifest. "
                "Note: the device must be configured to use CoAP.",
            )
        optional.add_argument(
            "-m",
            "--sign-image",
            action="store_true",
            help="Sign image. Use only when the bootloader on a device "
            "expects a signed FW image.",
        )
        optional.add_argument(
            "-r",
            "--priority",
            type=get_non_negative_int_argument,
            help="Set update priority >=0. [Default: 0].",
            default=0,
        )
        optional.add_argument(
            "--combined-image",
            action="store_true",
            help="Use combined package prepared by manifest-package-tool",
        )

    optional.add_argument(
        "-d",
        "--vendor-data",
        help="Path to a vendor custom data file - to be passed to "
        "the target devices.",
        type=get_argument_path,
    )

    optional.add_argument(
        "--cache-dir",
        help="Tool's cache directory. "
        'Must match the directory used by the "init" command.',
        type=Path,
        default=defaults.BASE_PATH,
    )

    optional.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit."
    )


def set_payload_format(delta_meta_file, combined_package, encrypted_digest):
    """Set the payload format."""
    if delta_meta_file.is_file():
        if encrypted_digest:
            raise AssertionError("Unexpected combination (Delta+Encrypted)")
        payload_format = PayloadFormat.PATCH
    elif combined_package is True:
        if encrypted_digest:
            payload_format = PayloadFormat.ENCRYPTED_COMBINED
        else:
            payload_format = PayloadFormat.COMBINED
    else:
        if encrypted_digest:
            payload_format = PayloadFormat.ENCRYPTED_RAW
        else:
            payload_format = PayloadFormat.RAW

    return payload_format


def create_dev_manifest(
    dev_cfg: dict,
    manifest_version: Type[ManifestAsnCodecBase],
    vendor_data_path: Path,
    payload_path: Path,
    payload_url: str,
    encrypted_digest: str,
    encrypted_size: int,
    priority: int,
    fw_version: str,
    sign_image: bool,
    component: str,
    combined_package: bool,
):
    """Create developer manifest."""
    payload_file = payload_path
    delta_meta_file = payload_file.with_suffix(".yaml")

    payload_format = set_payload_format(
        delta_meta_file, combined_package, encrypted_digest
    )

    input_cfg = {
        "vendor": {"vendor-id": dev_cfg["vendor-id"]},
        "device": {"class-id": dev_cfg["class-id"]},
        "payload": {
            "url": payload_url,
            "file-path": payload_path.as_posix(),
            "format": payload_format.value,
        },
    }

    if encrypted_digest:
        input_cfg["payload"]["encrypted"] = {
            "digest": encrypted_digest,
            "size": encrypted_size,
        }

    if priority is not None:
        input_cfg["priority"] = priority

    if manifest_version.get_name() != "v1":
        input_cfg["sign-image"] = sign_image
        input_cfg["component"] = component

    if vendor_data_path:
        input_cfg["vendor"]["custom-data-path"] = vendor_data_path.as_posix()

    signing_key = None
    if "signing-tool" in dev_cfg and dev_cfg["signing-tool"] is not None:
        input_cfg["signing-tool"] = dev_cfg["signing-tool"]
        signing_key = dev_cfg["key_file"]
    else:
        key_file = Path(dev_cfg["key_file"])
        if not key_file.is_file():
            raise AssertionError("{} not found".format(key_file.as_posix()))
        signing_key = key_file.read_bytes()

    logger.debug("input_cfg=\n%s", yaml.dump(input_cfg))

    manifest_bin = CreateAction.do_create(
        signing_key=signing_key,
        input_cfg=input_cfg,
        fw_version=fw_version,
        update_certificate=Path(dev_cfg["certificate"]),
        asn1_codec_class=manifest_version,
    )
    logger.info(
        "Created manifest in %s schema for %s update campaign",
        manifest_version.get_name(),
        "delta" if payload_format == PayloadFormat.PATCH else "full",
    )
    return manifest_bin


def bump_version(sem_ver: str):
    """Bump version."""
    nibbles = sem_ver.split(".")
    for i in range(2, -1, -1):
        nibble = int(nibbles[i]) + 1
        if nibble <= 999:
            nibbles[i] = nibble
            break
        nibbles[i] = 0
    return semantic_version_arg_factory("{}.{}.{}".format(*nibbles))


def load_cfg_and_get_fw_ver(
    args, manifest_version: Type[ManifestAsnCodecBase]
):
    """Load config file and get FW version."""
    if not args.cache_dir.is_dir():
        raise AssertionError(
            "Tool cache directory is missing. "
            'Execute "init" command to create it.'
        )

    component_name = getattr(args, "component_name", "MAIN")
    fw_migrate_ver = getattr(args, "fw_migrate_ver", None)
    cache_fw_version_file = args.cache_dir / defaults.UPDATE_VERSION
    cached_versions = {}
    fw_sem_ver = None

    # load dev_cfg
    with (args.cache_dir / defaults.DEV_CFG).open("rt") as fh:
        dev_cfg = yaml.safe_load(fh)

    # load cached_versions
    if "v1" not in manifest_version.get_name() or fw_migrate_ver:
        if cache_fw_version_file.is_file():
            with cache_fw_version_file.open("rt") as fh:
                cached_versions = yaml.safe_load(fh)

    # set fw_version
    if "v1" not in manifest_version.get_name():
        fw_version = (
            args.fw_version
            if args.fw_version
            else bump_version(cached_versions.get(component_name, "0.0.1"))
        )
        fw_sem_ver = fw_version
        logger.info("FW version: %s", fw_version)
    elif fw_migrate_ver:
        fw_version, fw_sem_ver = args.fw_migrate_ver
        logger.info("FW version: %d (%s)", fw_version, fw_sem_ver)
    else:
        fw_version = args.fw_version
        logger.info("FW version: %d", fw_version)

    # save cached_versions
    if fw_sem_ver:
        cached_versions[component_name] = fw_sem_ver
        with cache_fw_version_file.open("wt") as fh:
            yaml.dump(cached_versions, fh)

    return dev_cfg, fw_version


def entry_point(
    args,
    parser: argparse.ArgumentParser,
    manifest_version: Type[ManifestAsnCodecBase],
):
    """Entry point of the create command."""
    encrypted_digest = getattr(args, "encrypted_digest", None)
    encrypted_size = getattr(args, "encrypted_size", None)

    if encrypted_digest or encrypted_size:
        if not encrypted_digest or not encrypted_size:
            parser.error(
                "require --encrypted-digest and --encrypted-size "
                "or none of those."
            )

    dev_cfg, fw_version = load_cfg_and_get_fw_ver(args, manifest_version)

    manifest_bin = create_dev_manifest(
        dev_cfg=dev_cfg,
        manifest_version=manifest_version,
        vendor_data_path=args.vendor_data,
        payload_path=args.payload_path,
        payload_url=args.payload_url,
        encrypted_digest=encrypted_digest,
        encrypted_size=encrypted_size,
        priority=args.priority,
        fw_version=fw_version,
        sign_image=getattr(args, "sign_image", False),
        component=getattr(args, "component_name", None),
        combined_package=getattr(args, "combined_image", False),
    )

    with args.output as fh:
        fh.write(manifest_bin)
