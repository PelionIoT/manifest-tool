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
from manifesttool.package_tool.actions.parse import ParseAction
from manifesttool.package_tool.asn1.package_encoder import DescriptorAsnCodec
from manifesttool.package_tool.package_format.package_format \
    import DESCRIPTOR_FILE_NAME
from tests.conftest import package_data_generator

FW_SIZE_BITS = 1024 * 512
@pytest.mark.parametrize('pack_format', ['tar'])
def test_create_happy_day_action(
    tmp_path_factory,
    pack_format
):
    happy_day_data = package_data_generator(tmp_path_factory,FW_SIZE_BITS)

   # Create package
    CreateAction.do_create(happy_day_data['input_cfg'], \
        happy_day_data['out_file_name'], pack_format)

    ParseAction.do_parse(happy_day_data['out_file_name'])

@pytest.mark.parametrize('pack_format', ['tar'])
def test_create_happy_day_command(
    tmp_path_factory,
    pack_format
):

    happy_day_data = package_data_generator(tmp_path_factory,FW_SIZE_BITS)

    # Create package
    CreateAction.do_create(happy_day_data['input_cfg'], \
        happy_day_data['out_file_name'], pack_format)


    cmd = [
        'parse',
        '--package', happy_day_data['out_file_name']
    ]
    assert package_tool.entry_point(cmd) == 0
