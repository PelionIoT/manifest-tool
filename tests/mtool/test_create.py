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
import binascii
import uuid
from pathlib import Path
from typing import Type
import pytest
import yaml
import re
from enum import Enum
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from manifesttool.mtool import mtool, ecdsa_helper
from manifesttool.mtool.actions.create import CreateAction
from manifesttool.package_tool.actions.create import (
    CreateAction as PackageCreateAction,
)
from manifesttool.mtool.asn1 import ManifestAsnCodecBase, ManifestVersion
from manifesttool.mtool.asn1.v1 import ManifestAsnCodecV1
from manifesttool.mtool.asn1 import v3
from manifesttool.mtool.asn1 import v1
from tests.conftest import data_generator
from tests.conftest import encrypt_file

SCRIPT_DIR = Path(__file__).resolve().parent
GEN_DIR = SCRIPT_DIR / "test_data"

FILE_ID = 0

ENCRYPTION_KEY = bytearray.fromhex("0102030405060708090A0B0C0D0E0F10")


@pytest.mark.parametrize("fw_size", [512, 713, 4096, 100237, 512001])
@pytest.mark.parametrize(
    "manifest_codec,payload_format",
    [
        (v3.ManifestAsnCodecV3, "raw-binary"),
        (v1.ManifestAsnCodecV1, "raw-binary"),
        (v3.ManifestAsnCodecV3, "combined"),
        (v3.ManifestAsnCodecV3, "encrypted-raw"),
        (v3.ManifestAsnCodecV3, "encrypted-combined"),
    ],
)
def test_create_happy_day_full(
    tmp_path_factory, fw_size, manifest_codec, payload_format
):
    global FILE_ID
    GEN_DIR.mkdir(exist_ok=True)
    happy_day_data = data_generator(tmp_path_factory, fw_size, ENCRYPTION_KEY)

    payload_file_path = happy_day_data["fw_file"].as_posix()
    if payload_format in ("combined", "encrypted-combined"):
        generate_encrypted_package(happy_day_data)
        payload_file_path = happy_day_data["package_data"]["out_file_name"]

    manifest = None
    file_name_prefix = "f"

    input_cfg = {
        "vendor": {"domain": "izumanetworks.com"},
        "device": {"model-name": "my-device"},
        "priority": 15,
        "payload": {
            "url": "{}/{}_{}_payload.bin".format(
                GEN_DIR, FILE_ID, file_name_prefix
            ),
            "file-path": payload_file_path,
            "format": payload_format,
        },
        "component": "MAIN",
    }
    if issubclass(manifest_codec, ManifestAsnCodecV1):
        version = 100500
    else:
        version = "100.500.0"

        component = "MAIN"
        if payload_format in ("raw-binary", "combined") and (FILE_ID % 2) == 0:
            component = "TESTCOMP"
            input_cfg["component"] = component
        elif payload_format == "encrypted-raw":
            input_cfg["component"] = component
            # encrypted payload with dummy metadata
            input_cfg["payload"]["encrypted"] = {
                "digest": calc_digest(happy_day_data["encrypted_fw_file"]),
                "size": happy_day_data["encrypted_fw_file"].stat().st_size,
            }
            input_cfg["payload"][
                "url"
            ] = "../test_data/{}_{}_encrypted_payload.bin".format(
                FILE_ID, file_name_prefix
            )
        elif payload_format == "encrypted-combined":
            input_cfg["component"] = component
            # create encrypted package
            generate_encrypted_package(happy_day_data)
            # encrypted payload with dummy metadata
            input_cfg["payload"]["encrypted"] = {
                "digest": calc_digest(happy_day_data["encrypted_fw_file"]),
                "size": happy_day_data["encrypted_fw_file"].stat().st_size,
            }
            input_cfg["payload"][
                "url"
            ] = "../test_data/{}_{}_encrypted_payload.bin".format(
                FILE_ID, file_name_prefix
            )

        component_file = GEN_DIR / "{}_{}_component.txt".format(
            FILE_ID, file_name_prefix
        )
        component_file.write_text(component)

    manifest = CreateAction.do_create(
        signing_key=Path(happy_day_data["key_file"]).read_bytes(),
        input_cfg=input_cfg,
        fw_version=version,
        update_certificate=happy_day_data["certificate_file"],
        asn1_codec_class=manifest_codec,
    )

    create_test_data_file(
        happy_day_data,
        GEN_DIR,
        file_name_prefix,
        FILE_ID,
        manifest,
        manifest_codec,
        input_cfg,
        version,
    )

    payload_file = GEN_DIR / "{}_{}_payload.bin".format(
        FILE_ID, file_name_prefix
    )
    payload_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    orig_fw_file = GEN_DIR / "{}_{}_curr_fw.bin".format(
        FILE_ID, file_name_prefix
    )
    orig_fw_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    new_fw_file = GEN_DIR / "{}_{}_final_image.bin".format(
        FILE_ID, file_name_prefix
    )
    new_fw_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    FILE_ID += 1

    print(
        "Full manifest in HEX to be viewed on "
        "https://asn1.io/asn1playground/ \n"
        + binascii.hexlify(manifest).decode("utf-8")
    )


def generate_encrypted_package(happy_day_data):
    # Create package
    PackageCreateAction.do_create(
        happy_day_data["package_data"]["input_cfg"],
        happy_day_data["package_data"]["out_file_name"],
        "tar",
    )

    encrypt_file(
        happy_day_data["package_data"]["out_file_name"],
        happy_day_data["encrypted_fw_file"],
        happy_day_data["encryption_key"],
    )


def calc_digest(payload_file):
    hash_ctx = hashes.Hash(hashes.SHA256(), backends.default_backend())
    buf = payload_file.read_bytes()
    hash_ctx.update(buf)
    digest = hash_ctx.finalize()

    return digest.hex()


def create_test_data_file(
    happy_day_data,
    test_dir,
    file_name_prefix,
    file_id,
    manifest,
    manifest_codec,
    input_cfg,
    version,
):
    version_file = GEN_DIR / "{}_{}_version_{}.txt".format(
        file_id, file_name_prefix, manifest_codec.get_name()
    )
    version_file.write_text(str(version))

    manifest_file = test_dir / "{}_{}_manifest_{}.bin".format(
        file_id, file_name_prefix, manifest_codec.get_name()
    )
    if "encrypted" in input_cfg["payload"]:
        # mimic service behaviour,
        # concatenate DER with dummy aes-128-bit key
        manifest_file.write_bytes(
            manifest + bytearray.fromhex("8110") + ENCRYPTION_KEY
        )
    else:
        manifest_file.write_bytes(manifest)

    certificate_file = test_dir / "{}_{}_certificate.bin".format(
        file_id, file_name_prefix
    )
    certificate_file.write_bytes(
        happy_day_data["certificate_file"].read_bytes()
    )

    if input_cfg["payload"]["format"] == "encrypted-raw":
        encrypted_payload_file = (
            test_dir
            / "{}_{}_encrypted_payload.bin".format(file_id, file_name_prefix)
        )
        encrypted_payload_file.write_bytes(
            happy_day_data["encrypted_fw_file"].read_bytes()
        )

    dom = manifest_codec.decode(manifest, None)

    if manifest_codec.get_name() == "v3":
        vendor_id_bytes = dom["manifest"]["vendor-id"]
        class_id_bytes = dom["manifest"]["class-id"]
    elif manifest_codec.get_name() == "v1":
        vendor_id_bytes = dom["resource"]["resource"]["manifest"]["vendorId"]
        class_id_bytes = dom["resource"]["resource"]["manifest"]["classId"]
    else:
        raise AssertionError(
            "invalid manifest version " + manifest_codec.get_name()
        )

    vendor_id_file = test_dir / "{}_{}_vendor_id.bin".format(
        file_id, file_name_prefix
    )
    vendor_id_file.write_bytes(vendor_id_bytes)

    class_id_file = test_dir / "{}_{}_class_id.bin".format(
        file_id, file_name_prefix
    )
    class_id_file.write_bytes(class_id_bytes)

    key_file = test_dir / "{}_{}_priv_key.bin".format(
        file_id, file_name_prefix
    )
    private_key_data = Path(happy_day_data["key_file"]).read_bytes()
    key_file.write_bytes(private_key_data)

    public_key = ecdsa_helper.public_key_from_private(private_key_data)
    public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)

    public_key_file = test_dir / "{}_{}_pub_key.bin".format(
        file_id, file_name_prefix
    )
    public_key_file.write_bytes(public_key_bytes)


@pytest.mark.parametrize("fw_size", [512, 713, 4096, 100237, 512001])
def test_create_happy_day_delta(tmp_path_factory, fw_size):
    global FILE_ID
    GEN_DIR.mkdir(exist_ok=True)
    happy_day_data = data_generator(tmp_path_factory, fw_size)

    manifest = None
    file_name_prefix = "d"

    for manifest_version in ManifestVersion.list_codecs():
        input_cfg = {
            "vendor": {"domain": "izumanetworks.com"},
            "device": {"model-name": "my-device"},
            "priority": 15,
            "payload": {
                "url": "../test_data/{}_{}_payload.bin".format(
                    FILE_ID, file_name_prefix
                ),
                "file-path": happy_day_data["delta_file"].as_posix(),
                "format": "arm-patch-stream",
            },
            "sign-image": "v1" not in manifest_version.get_name(),  # Bool
        }
        if issubclass(manifest_version, ManifestAsnCodecV1):
            version = 100500
        else:
            version = "100.500.0"

            component = "MAIN"
            if (FILE_ID % 2) == 0:
                component = "TESTCOMP"
                input_cfg["component"] = component
            elif (FILE_ID % 3) == 0:
                input_cfg["component"] = component

            component_file = GEN_DIR / "{}_{}_component.txt".format(
                FILE_ID, file_name_prefix
            )
            component_file.write_text(component)

        manifest = CreateAction.do_create(
            signing_key=Path(happy_day_data["key_file"]).read_bytes(),
            input_cfg=input_cfg,
            update_certificate=happy_day_data["certificate_file"],
            fw_version=version,
            asn1_codec_class=manifest_version,
        )

        create_test_data_file(
            happy_day_data,
            GEN_DIR,
            file_name_prefix,
            FILE_ID,
            manifest,
            manifest_version,
            input_cfg,
            version,
        )

        payload_file = GEN_DIR / "{}_{}_payload.bin".format(
            FILE_ID, file_name_prefix
        )
        payload_file.write_bytes(happy_day_data["delta_file"].read_bytes())

        orig_fw_file = GEN_DIR / "{}_{}_curr_fw.bin".format(
            FILE_ID, file_name_prefix
        )
        orig_fw_file.write_bytes(happy_day_data["fw_file"].read_bytes())

        new_fw_file = GEN_DIR / "{}_{}_final_image.bin".format(
            FILE_ID, file_name_prefix
        )
        new_fw_file.write_bytes(happy_day_data["new_fw_file"].read_bytes())

    FILE_ID += 1

    print(
        "Delta manifest in HEX to be viewed on "
        "https://asn1.io/asn1playground/ \n"
        + binascii.hexlify(manifest).decode("utf-8")
    )


class UpdateType(Enum):
    FULL = (1,)
    DELTA = (2,)
    COMBINED = 3


@pytest.mark.parametrize("manifest_version", ManifestVersion.list_codecs())
def test_cli_delta(
    happy_day_data, manifest_version: Type[ManifestAsnCodecBase]
):
    cli_test_common(happy_day_data, manifest_version, UpdateType.FULL)


@pytest.mark.parametrize("manifest_version", ManifestVersion.list_codecs())
def test_cli_full(
    happy_day_data, manifest_version: Type[ManifestAsnCodecBase]
):
    cli_test_common(happy_day_data, manifest_version, UpdateType.DELTA)


# @pytest.mark.parametrize("manifest_version", ManifestVersion.list_codecs())
@pytest.mark.parametrize("manifest_version", [v1.ManifestAsnCodecV1])
def test_cli_external_signing(
    tmp_path_factory, manifest_version: Type[ManifestAsnCodecBase], caplog
):
    happy_day_data = data_generator(
        tmp_path_factory, size=512, signing_tool=True
    )
    happy_day_data["key_file"] = "123"
    data_cfg = cli_test_common(
        happy_day_data,
        manifest_version,
        UpdateType.DELTA,
        external_signing=True,
    )

    expected_message = r"^Running {} {} {} (.+?) to sign manifest.".format(
        data_cfg["signing-tool"], "sha256", happy_day_data["key_file"]
    )
    matching_messages = [
        message
        for message in caplog.messages
        if re.match(expected_message, message)
    ]

    assert matching_messages


@pytest.mark.parametrize("manifest_version", [v3.ManifestAsnCodecV3])
@pytest.mark.parametrize("pack_format", ["tar"])
def test_cli_combined(
    happy_day_data, manifest_version: Type[ManifestAsnCodecBase], pack_format
):
    # Create package
    PackageCreateAction.do_create(
        happy_day_data["package_data"]["input_cfg"],
        happy_day_data["package_data"]["out_file_name"],
        pack_format,
    )
    cli_test_common(happy_day_data, manifest_version, UpdateType.COMBINED)


def cli_test_common(
    happy_day_data, manifest_version, update_type, external_signing=False
):
    tmp_cfg = happy_day_data["tmp_path"] / "input.yaml"
    output_manifest = happy_day_data["tmp_path"] / "foo.bin"
    if update_type == UpdateType.DELTA:
        file_path = happy_day_data["delta_file"].as_posix()
        file_format = "arm-patch-stream"
    elif update_type == UpdateType.COMBINED:
        file_path = happy_day_data["package_data"]["out_file_name"]
        file_format = "combined"
    else:
        file_path = happy_day_data["fw_file"].as_posix()
        file_format = "raw-binary"

    data = {
        "vendor": {"domain": "izumanetworks.com"},
        "device": {"model-name": "my-device"},
        "priority": 15,
        "payload": {
            "url": "https://my.server.com/some.file?new=1",
            "file-path": file_path,
            "format": file_format,
        },
    }

    if external_signing:
        signing_tool = happy_day_data["signing_tool"].as_posix()
        data["signing-tool"] = signing_tool

    with tmp_cfg.open("wt") as fh:
        yaml.dump(data, fh)

    action = "create"
    if "v1" in manifest_version.get_name():
        action = "create-v1"
    cmd = [
        "--debug",
        action,
        "--config",
        tmp_cfg.as_posix(),
        "--key",
        happy_day_data["key_file"],
        "--output",
        output_manifest.as_posix(),
    ]
    if manifest_version.get_name() == "v1":
        cmd.extend(
            [
                "--update-certificate",
                happy_day_data["certificate_file"].as_posix(),
            ]
        )
    else:
        cmd.extend(["--fw-version", "100.0.500"])
    assert 0 == mtool.entry_point(cmd)

    return data


@pytest.mark.parametrize("manifest_version", ManifestVersion.list_codecs())
def test_create_happy_day_with_ids(happy_day_data, manifest_version):
    tmp_cfg = happy_day_data["tmp_path"] / "input.yaml"
    output_manifest = happy_day_data["tmp_path"] / "foo.bin"
    with tmp_cfg.open("wt") as fh:
        yaml.dump(
            {
                "vendor": {"vendor-id": uuid.uuid4().hex},
                "device": {"class-id": uuid.uuid4().hex},
                "priority": 15,
                "payload": {
                    "url": "https://my.server.com/some.file?new=1",
                    "file-path": happy_day_data["delta_file"].as_posix(),
                    "format": "arm-patch-stream",
                },
            },
            fh,
        )
    action = "create"
    if "v1" in manifest_version.get_name():
        action = "create-v1"
    cmd = [
        "--debug",
        action,
        "--config",
        tmp_cfg.as_posix(),
        "--key",
        happy_day_data["key_file"],
        "--output",
        output_manifest.as_posix(),
    ]

    if manifest_version.get_name() == "v1":
        cmd.extend(
            [
                "--update-certificate",
                happy_day_data["certificate_file"].as_posix(),
            ]
        )
    else:
        cmd.extend(["--fw-version", "100.500.8"])

    ret_code = mtool.entry_point(cmd)

    assert ret_code == 0


@pytest.mark.parametrize(
    "manifest_codec,payload_format",
    [
        (v3.ManifestAsnCodecV3, "raw-binary"),
        (v3.ManifestAsnCodecV3, "arm-patch-stream"),
        (v1.ManifestAsnCodecV1, "raw-binary"),
        (v1.ManifestAsnCodecV1, "arm-patch-stream"),
    ],
)
def test_create_happy_day_with_external_signing(
    tmp_path_factory, happy_day_data, manifest_codec, payload_format, caplog
):
    global FILE_ID
    GEN_DIR.mkdir(exist_ok=True)
    happy_day_data = data_generator(
        tmp_path_factory, size=512, encryption_key=None, signing_tool=True
    )

    manifest = None
    payload_file_path = None
    version = None
    file_name_prefix = "e"

    if payload_format == "raw-binary":
        payload_file_path = happy_day_data["fw_file"].as_posix()
    else:
        payload_file_path = happy_day_data["delta_file"].as_posix()

    input_cfg = {
        "vendor": {"domain": "izumanetworks.com"},
        "device": {"model-name": "my-device"},
        "priority": 15,
        "payload": {
            "url": "{}/{}_{}_payload.bin".format(
                GEN_DIR, FILE_ID, file_name_prefix
            ),
            "file-path": payload_file_path,
            "format": payload_format,
        },
        "component": "MAIN",
        "signing-tool": happy_day_data["signing_tool"].as_posix(),
    }

    if issubclass(manifest_codec, ManifestAsnCodecV1):
        version = 100500
    else:
        version = "100.500.0"

    manifest = CreateAction.do_create(
        signing_key=happy_day_data["key_file"],
        input_cfg=input_cfg,
        fw_version=version,
        update_certificate=happy_day_data["certificate_file"],
        asn1_codec_class=manifest_codec,
    )

    create_test_data_file(
        happy_day_data,
        GEN_DIR,
        file_name_prefix,
        FILE_ID,
        manifest,
        manifest_codec,
        input_cfg,
        version,
    )

    payload_file = GEN_DIR / "{}_{}_payload.bin".format(
        FILE_ID, file_name_prefix
    )
    payload_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    orig_fw_file = GEN_DIR / "{}_{}_curr_fw.bin".format(
        FILE_ID, file_name_prefix
    )
    orig_fw_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    new_fw_file = GEN_DIR / "{}_{}_final_image.bin".format(
        FILE_ID, file_name_prefix
    )
    new_fw_file.write_bytes(happy_day_data["fw_file"].read_bytes())

    FILE_ID += 1

    expected_message = r"^Running {} {} {} (.+?) to sign manifest.".format(
        input_cfg["signing-tool"], "sha256", happy_day_data["key_file"]
    )
    matching_messages = [
        message
        for message in caplog.messages
        if re.match(expected_message, message)
    ]

    assert matching_messages

    print(
        "Full manifest in HEX to be viewed on "
        "https://asn1.io/asn1playground/ \n"
        + binascii.hexlify(manifest).decode("utf-8")
    )


"""  """
