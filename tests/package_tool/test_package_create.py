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
import pytest
import tarfile
from manifesttool.package_tool.package_tool import entry_point
from manifesttool.package_tool.actions.create import CreateAction
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec
from manifesttool.package_tool.package_format.package_format \
    import DESCRIPTOR_FILE_NAME


@pytest.fixture(scope="session")
def test_files(tmp_path_factory):
    fw_size_bits = 1024 * 512

    tmp_path  = tmp_path_factory.mktemp("package_data")

    img1_name = tmp_path  / 'first.bin'
    img1_data =  os.urandom(fw_size_bits)
    img1_name.write_bytes(img1_data)

    img2_name = tmp_path  / 'second.bin'
    img2_data = os.urandom(fw_size_bits)
    img2_name.write_bytes(img2_data)

    output_dir = tmp_path_factory.mktemp("output")
    out_file_name = output_dir /'output.tar'

    input_cfg = {
        'package-format': 'tar',
        'alignment-size': 1,
        'images': [
                {
                    'img_id': 'img1_name',
                    'vendor_data': 'ca34_NM',
                    'file_name': img1_name.as_posix()
                },
                {
                    'img_id': 'img2_name',
                    'vendor_data': 'VER1.2',
                    'file_name':  img2_name.as_posix()
                }
        ]
    }
    CreateAction.do_create(input_cfg, out_file_name,"tar")

    return {
        "package_file" : out_file_name,
        "1img" : img1_name.as_posix(),
        "2img" : img2_name.as_posix(),
        "output_dir" : output_dir
    }

def test_cli_generate_tar_package_happy_day(tmp_path, test_files):

    # try extract all tar file
    my_tar = tarfile.open(test_files['package_file'])
    my_tar.extract(DESCRIPTOR_FILE_NAME,tmp_path)
    my_tar.extract(os.path.basename(test_files['1img']), \
        test_files['output_dir'])
    my_tar.extract(os.path.basename(test_files['2img']), \
        test_files['output_dir'])
    my_tar.close()

    # read the descriptor
    with open(tmp_path / DESCRIPTOR_FILE_NAME, "rb") as fh:
        asn1der = fh.read() 

    # try to decode the descriptor
    DescriptorAsnCodec.decode(asn1der)

