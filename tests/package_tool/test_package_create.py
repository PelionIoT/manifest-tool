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
import os
import os.path
import tarfile
import pytest
import yaml
from manifesttool.package_tool.package_tool import entry_point
from manifesttool.package_tool import package_tool
from manifesttool.package_tool.actions.create import CreateAction
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec
from manifesttool.package_tool.package_format.package_format import (
    DESCRIPTOR_FILE_NAME,
)
from tests.conftest import package_data_generator

FW_SIZE_BITS = 1024 * 512


@pytest.mark.parametrize("pack_format", ["tar"])
def test_create_happy_day_action(tmp_path_factory, pack_format):
    happy_day_data = package_data_generator(tmp_path_factory, FW_SIZE_BITS)

    # Create package
    CreateAction.do_create(
        happy_day_data["input_cfg"],
        happy_day_data["out_file_name"],
        pack_format,
    )

    check_tar_package(happy_day_data)


@pytest.mark.parametrize("pack_format", ["tar"])
def test_create_happy_day_command(tmp_path_factory, pack_format):

    happy_day_data = package_data_generator(tmp_path_factory, FW_SIZE_BITS)

    cmd = [
        "create",
        "--config",
        happy_day_data["tmp_cfg"],
        "--format",
        pack_format,
        "--image-alignment-size",
        "1",
        "--output",
        happy_day_data["out_file_name"],
    ]
    assert package_tool.entry_point(cmd) == 0

    check_tar_package(happy_day_data)


def check_tar_package_file(tar_file, file_name, expected_size):

    with tar_file.extractfile(file_name) as fh:
        fh.seek(0, os.SEEK_END)
        file_size = fh.tell()
        assert file_size == expected_size


def check_descriptor_file(tar_file, file_name, input_config):
    with tar_file.extractfile(file_name) as fh:
        asn1der = fh.read()
        # decode the descriptor
        asn1 = DescriptorAsnCodec.decode(asn1der)
        assert len(input_config["images"]) == asn1["num-of-images"]
        for asn_image, config_image in zip(
            asn1["descriptors-array"], input_config["images"]
        ):
            assert asn_image["id"] == config_image["sub_comp_name"].encode(
                "ASCII"
            )
            assert asn_image["vendor-data-size"] == len(
                config_image["vendor_data"]
            )
            assert asn_image["vendor-data"] == config_image[
                "vendor_data"
            ].encode("ASCII")


def check_tar_package(happy_day_data):
    # extract tar file
    with tarfile.open(happy_day_data["out_file_name"], "r:") as tar_arch:
        check_tar_package_file(
            tar_arch,
            os.path.basename(happy_day_data["1img_id"]),
            happy_day_data["1img_size"],
        )
        check_tar_package_file(
            tar_arch,
            os.path.basename(happy_day_data["2img_id"]),
            happy_day_data["2img_size"],
        )
        # Check descriptor
        check_descriptor_file(
            tar_arch, DESCRIPTOR_FILE_NAME, happy_day_data["input_cfg"]
        )
