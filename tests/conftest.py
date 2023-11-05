# ----------------------------------------------------------------------------
# Copyright 2019-2022 Izuma Networks
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
"""Configuration test."""
import contextlib
import os
import uuid
from pathlib import Path
import time
import yaml
import random
import pytest
import platform
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from manifesttool import armbsdiff
from manifesttool.delta_tool import delta_tool
from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.actions import init as dev_init


@pytest.fixture(scope="session")
def happy_day_data(tmp_path_factory):
    """Happy day data."""
    yield data_generator(tmp_path_factory, size=512)


@pytest.fixture
def timeless(monkeypatch):
    """Timeless."""
    timeless.cur_time = time.time()

    def sleep_mock(seconds):
        """Sleep mock."""
        timeless.cur_time += seconds

    def time_mock() -> float:
        """Time mock."""
        return timeless.cur_time

    monkeypatch.setattr(time, "sleep", sleep_mock)
    monkeypatch.setattr(time, "time", time_mock)


# Candidate image encryption is done using AES-CCM.
# Effective pages of 1016 image bytes.
# AES-CCM tag of size 8 bytes placed at the *start* of each output page.
# Total of 1024 bytes per output page.
# The nonce/IV of the first block is 1, and it is increased by 1 for each page.
# The nonce/IV size is 8 bytes (little endian).
TAG_SIZE_BYTES = 8

NONCE_SIZE_BYTES = 8
NONCE_BYTE_ORDER = "little"

PAGE_SIZE_BYTES = 1024
EFFECTIVE_PAGE_SIZE_BYTES = PAGE_SIZE_BYTES - TAG_SIZE_BYTES


def encrypt_file(
    input_file_name: str, output_file_name: str, key: bytes
) -> None:
    """Encrypt file."""
    input_file = open(input_file_name, "rb")
    output_file = open(output_file_name, "wb")

    # AES-CCM instance.
    aesccm = AESCCM(key, tag_length=TAG_SIZE_BYTES)

    # Nonce is starting with 1 for the first page.
    nonce_value = 1

    while True:

        data_page = input_file.read(EFFECTIVE_PAGE_SIZE_BYTES)
        if len(data_page) == 0:
            break

        # Convert nonce to machine representation.
        nonce = nonce_value.to_bytes(NONCE_SIZE_BYTES, NONCE_BYTE_ORDER)

        # Encrypt page.
        aesccm_output = aesccm.encrypt(nonce, data_page, None)

        encrypted_data = aesccm_output[0 : len(data_page)]
        tag = aesccm_output[len(data_page) :]

        # Verify sizes are as they are expected to be.
        assert len(tag) == TAG_SIZE_BYTES
        assert len(encrypted_data) + len(tag) == len(aesccm_output)

        # Write tag and encrypted data (in reverse order compared to
        # output of encryption function).
        output_file.write(tag)
        output_file.write(encrypted_data)

        nonce_value += 1

    input_file.close()
    output_file.close()


def data_generator(
    tmp_path_factory,
    size,
    encryption_key: bytes = None,
    signing_tool: bool = False,
):
    """Generate data."""
    tmp_path = tmp_path_factory.mktemp("data")
    key_file = tmp_path / "dev.key.pem"
    certificate_file = tmp_path / "dev.cert.der"
    dev_init.generate_credentials(
        key_file=key_file, cert_file=certificate_file, cred_valid_time=8
    )
    bsdiff_version = armbsdiff.get_version().encode("utf-8")
    fw_file = tmp_path / "fw.bin"
    fw_data = bsdiff_version + os.urandom(size - len(bsdiff_version))
    fw_file.write_bytes(fw_data)
    new_fw_file = tmp_path / "new_fw.bin"
    new_fw_data = fw_data + os.urandom(512)
    new_fw_file.write_bytes(new_fw_data)
    delta_file = tmp_path / "delta.bin"
    delta_tool.generate_delta(
        orig_fw=fw_file,
        new_fw=new_fw_file,
        output_delta_file=delta_file,
        block_size=512,
        threshold=60,
    )

    if encryption_key:
        encrypted_fw_file = tmp_path / "encrypted_fw.bin"
        encrypt_file(fw_file, encrypted_fw_file, encryption_key)
    else:
        encrypted_fw_file = None

    class_id = uuid.uuid4()
    vendor_id = uuid.uuid4()

    signing_tool_path = None
    if signing_tool:
        # signing_tool_path = tmp_path / "sign"
        signing_tool_path = generate_external_signing_tool(tmp_path / "sign")

    dev_cfg = tmp_path / "dev.cfg.yaml"
    dev_init.generate_developer_config(
        key_file=key_file,
        cert_file=certificate_file,
        config=dev_cfg,
        class_id=class_id,
        vendor_id=vendor_id,
        signing_tool=signing_tool_path,
        signing_key_id=key_file,
    )

    api_config_path = tmp_path / "dev.cloud_cfg.yaml"
    dev_init.generate_service_config(
        access_key="sdsdadadadsdadasdadsadasdas",
        api_url=defaults.API_GW,
        api_config_path=api_config_path,
    )

    package_data = package_data_generator(tmp_path_factory, 1024 * 512)

    return {
        "fw_file": fw_file,
        "new_fw_file": new_fw_file,
        "encrypted_fw_file": encrypted_fw_file,
        "delta_file": delta_file,
        "key_file": key_file,
        "certificate_file": certificate_file,
        "tmp_path": tmp_path,
        "dev_cfg": dev_cfg,
        "api_config_path": api_config_path,
        "package_data": package_data,
        "encryption_key": encryption_key,
        "signing_tool": signing_tool_path,
    }


def package_data_generator(tmp_path_factory, max_image_size):
    """Package data generator."""
    tmp_path = tmp_path_factory.mktemp("package_data")
    img1_name = tmp_path / "first.bin"
    img1_size = random.randint(1024, max_image_size)
    img1_data = os.urandom(img1_size)
    img1_name.write_bytes(img1_data)
    img2_name = tmp_path / "second.bin"
    img2_size = random.randint(1024, max_image_size)
    img2_data = os.urandom(img2_size)
    img2_name.write_bytes(img2_data)
    out_file_name = tmp_path / "package_file"
    img1_id = "img1_id"
    img2_id = "img2_id"

    tmp_cfg = tmp_path / "package_config.yaml"

    with tmp_cfg.open("wt") as fh:
        yaml.dump(
            {
                "images": [
                    {
                        "sub_comp_name": img1_id,
                        "vendor_data": "ca34_NM",
                        "file_name": img1_name.as_posix(),
                    },
                    {
                        "sub_comp_name": img2_id,
                        "vendor_data": "VER1.2",
                        "file_name": img2_name.as_posix(),
                    },
                ]
            },
            fh,
        )

    with open(tmp_cfg, "rb") as config_fh:
        input_cfg = yaml.safe_load(config_fh)

    return {
        "1img_id": img1_id,
        "2img_id": img2_id,
        "1img_size": img1_size,
        "2img_size": img2_size,
        "out_file_name": out_file_name.as_posix(),
        "tmp_cfg": tmp_cfg.as_posix(),
        "input_cfg": input_cfg,
    }


@contextlib.contextmanager
def working_directory(path: Path):
    """Get working directory."""
    current = Path.cwd()
    os.chdir(path.as_posix())
    try:
        yield
    finally:
        os.chdir(current.as_posix())


def generate_external_signing_tool(file_path):
    """Generate external signing script, based on the OS."""
    if platform.system() == "Windows":
        script_extension = ".bat"
        parameter_sign = "%"
        script_interp = ""
    else:
        script_extension = ".sh"
        parameter_sign = "$"
        script_interp = "#!/bin/bash\n"

    full_file_name = file_path.with_suffix(script_extension)
    print("Full file name " + str(full_file_name))
    script_line = (
        'openssl dgst -debug -binary -"'
        + parameter_sign
        + '1" -keyform PEM -sign "'
        + parameter_sign
        + '2" -out "'
        + parameter_sign
        + '4" "'
        + parameter_sign
        + '3"'
    )
    script_content = script_interp + script_line

    with open(full_file_name, "w") as script_file:
        script_file.write(script_content)

    # The script should be executable
    os.chmod(full_file_name, 0x755)

    print("external signing tool script was created")

    return full_file_name
