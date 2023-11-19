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
"""Create action."""
import argparse
import logging
import time
from pathlib import Path
from typing import Type

import tempfile
import subprocess
import os
import jsonschema
import yaml

from manifesttool.common.common_helpers import get_argument_path
from manifesttool.common.common_helpers import get_non_negative_int_argument
from manifesttool.mtool.actions import semantic_version_arg_factory
from manifesttool.mtool.actions import semver_as_tuple_arg_factory
from manifesttool.mtool.asn1 import ManifestAsnCodecBase
from manifesttool.mtool.asn1.v1 import ManifestAsnCodecV1
from manifesttool.mtool import ecdsa_helper

MTOOL_PATH = Path(__file__).resolve().parent.parent

logger = logging.getLogger("manifest-tool-create")


def create_signature(
    input_cfg: dict,
    raw_signature: bool,
    der_manifest: bytes,
    signing_key,
) -> bytes:
    """Create signature."""
    if "signing-tool" in input_cfg:
        try:
            signing_tool = input_cfg["signing-tool"]
            signing_tool_path = os.path.join(os.getcwd(), signing_tool)
            digest_algo = "sha256"
            infile = None
            with tempfile.NamedTemporaryFile(delete=False) as f:
                infile = f.name
                f.write(der_manifest)
                f.flush()
                logger.debug("Temporary manifest file: %s", infile)
            outfile = None
            with tempfile.NamedTemporaryFile(delete=False) as f:
                outfile = f.name
                logger.debug("Temporary signature file: %s", outfile)

            cmd = [
                signing_tool_path,
                digest_algo,
                signing_key,
                infile,
                outfile,
            ]
            logger.info("Running %s to sign manifest.", (" ".join(cmd)))
            # pylint: disable=R1732
            process = subprocess.Popen(cmd)  # nosec
            process.wait()
            process.terminate()
        except Exception:  # pylint: disable=broad-except
            logger.critical("Signing tool failed.")
            raise
        with open(outfile, "rb") as f:
            signature = f.read()
    else:
        logger.debug("no external signing tool")
        signature = ecdsa_helper.ecdsa_sign(der_manifest, signing_key)
    if raw_signature:
        signature = ecdsa_helper.signature_der_to_raw(signature)

    return signature


class CreateAction:
    """CreateAction class."""

    @staticmethod
    def register_parser_args(
        parser: argparse.ArgumentParser, schema_version: str
    ):
        """Register parser arguments."""
        required = parser.add_argument_group("required arguments")
        optional = parser.add_argument_group("optional arguments")

        required.add_argument(
            "-c",
            "--config",
            help="Path to the manifest tool configuration file.",
            metavar="YAML",
            type=argparse.FileType("rb"),
            required=True,
        )

        required.add_argument(
            "-k",
            "--key",
            help="""
            A private key file that sings the manifest.
            Could be a path to the PEM format private key file.
            It could also be an identifier for a private key,
            if `signing-tool` value is supplied in the configuration file
            """,
            metavar="KEY",
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

            required.add_argument(
                "--update-certificate",
                type=get_argument_path,
                help="Path to the update certificate file.",
                required=True,
            )
        else:
            required.add_argument(
                "-v",
                "--fw-version",
                type=semantic_version_arg_factory,
                help="Version number of the candidate image in SemVer format. "
                "Min. 0.0.1, max 999.999.999. "
                "Must be bigger than the version currently "
                "in the device(s).",
                required=True,
            )

        required.add_argument(
            "-o",
            "--output",
            help="Output manifest filename.",
            type=argparse.FileType("wb"),
            required=True,
        )

        optional.add_argument(
            "-h",
            "--help",
            action="help",
            help="Show this help message and exit.",
        )

    @staticmethod
    def do_create(
        signing_key,
        input_cfg: dict,
        fw_version,
        update_certificate: Path,
        asn1_codec_class: Type[ManifestAsnCodecBase],
    ) -> bytes:
        """Create method."""
        assert fw_version is not None

        codec = asn1_codec_class()

        # validate input against manifest-input-schema.json
        schema_path = MTOOL_PATH / "manifest-input-schema.json"
        with schema_path.open("rb") as fh:
            input_schema = yaml.safe_load(fh)
            if isinstance(codec, ManifestAsnCodecV1):
                # priority field is optional for v1
                # delete it from required list
                input_schema["required"].remove("priority")
            jsonschema.validate(input_cfg, input_schema)

        raw_signature = True
        if isinstance(codec, ManifestAsnCodecV1):
            raw_signature = False
            cert_data = update_certificate.read_bytes()
            codec.set_update_certificate(cert_data)
        installed_digest = codec.process_input_config(fw_version, input_cfg)

        if input_cfg.get("sign-image"):
            if isinstance(codec, ManifestAsnCodecV1):
                raise AssertionError(
                    "sign-image is unexpected for manifest schema v1"
                )
            if "signing-tool" in input_cfg:
                raise AssertionError(
                    "sign-image option is not supported together \
                    with signing-tool option"
                )
            signature = ecdsa_helper.ecdsa_sign_prehashed(
                installed_digest, signing_key
            )
            codec.set_image_signature(
                ecdsa_helper.signature_der_to_raw(signature)
            )
        else:
            codec.set_image_signature(bytes())

        der_manifest = codec.get_signed_data()

        signature = create_signature(
            input_cfg, raw_signature, der_manifest, signing_key
        )
        manifest_bin = codec.get_der_signed_resource(signature)

        logger.info(
            "Attention: When updating Mbed OS devices,"
            " candidate features must match the device's"
            " bootloader features. Incompatibility may"
            " result in damaged devices."
        )

        return manifest_bin

    @classmethod
    def entry_point(
        cls, args: argparse.Namespace, asn1_codec: Type[ManifestAsnCodecBase]
    ) -> None:
        """Entry point method."""
        input_cfg = yaml.safe_load(args.config)

        if getattr(args, "fw_migrate_ver", None):
            fw_version = args.fw_migrate_ver[0]
        else:
            fw_version = args.fw_version

        if "signing-tool" in input_cfg:
            # If signing-tool option is supplied
            # The key argument is propagated as is, without any manipulations
            # It will be used, later on, together with the signing-tool
            signing_key = args.key
        else:
            key_file = Path(args.key)
            signing_key = key_file.read_bytes()

        manifest_bin = cls.do_create(
            signing_key=signing_key,
            input_cfg=input_cfg,
            fw_version=fw_version,
            update_certificate=getattr(args, "update_certificate", None),
            asn1_codec_class=asn1_codec,
        )
        with args.output as fh:
            fh.write(manifest_bin)
