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

import os

import pytest

from manifesttool import armbsdiff
from manifesttool.delta_tool.delta_tool import entry_point
from manifesttool.delta_tool.delta_tool import generate_delta


@pytest.fixture(scope="session")
def test_files(tmp_path_factory):
    fw_size_bits = 1024 * 512

    temp_dir = tmp_path_factory.mktemp("data")
    current_bsdiff_version = armbsdiff.get_version().encode('utf-8')
    unsupported_bsdiff_version = b'PELION/BSDIFF666'

    orig_fw_name = temp_dir / 'orig_fw.bin'
    orig_fw_data = current_bsdiff_version + os.urandom(fw_size_bits)
    orig_fw_name.write_bytes(orig_fw_data)

    new_add_fw_name = temp_dir / 'new_fw.bin'
    new_add_fw_data = current_bsdiff_version + os.urandom(
        512) + orig_fw_data + os.urandom(512)
    new_add_fw_name.write_bytes(new_add_fw_data)

    other_fw_name = temp_dir / 'other_fw.bin'
    other_fw_data = unsupported_bsdiff_version + os.urandom(fw_size_bits)
    other_fw_name.write_bytes(other_fw_data)

    return {
        'orig_fw': orig_fw_name,
        'new_fw': new_add_fw_name,
        'other_fw': other_fw_name,
    }


def test_generate_delta_happy_day(tmp_path, test_files):
    delta_file = tmp_path / 'delta.bin'
    generate_delta(
        test_files['orig_fw'],
        test_files['new_fw'],
        delta_file,
        512,
        60
    )
    print('Delta-file-size={delta} new-file-size={new}'.format(
        delta=len(delta_file.read_bytes()),
        new=len(test_files['new_fw'].read_bytes())))

def test_cli_generate_delta_happy_day(tmp_path, test_files):
    delta_file = tmp_path / 'delta.bin'
    cmd = [
        '--current-fw', test_files['orig_fw'].as_posix(),
        '--new-fw', test_files['new_fw'].as_posix(),
        '--output', delta_file.as_posix(),
        '--block-size', '1024'
    ]
    assert 0 == entry_point(cmd)
    print('Delta-file-size={delta} new-file-size={new}'.format(
        delta=len(delta_file.read_bytes()),
        new=len(test_files['new_fw'].read_bytes())))

def test_cli_generate_delta_happy_day_skip_check(tmp_path, test_files):
    delta_file = tmp_path / 'delta.bin'
    cmd = [
        '--current-fw', test_files['orig_fw'].as_posix(),
        '--new-fw', test_files['other_fw'].as_posix(),
        '--output', delta_file.as_posix(),
        '--block-size', '1024',
        '--skip-size-check'
    ]
    assert 0 == entry_point(cmd)
    print('Delta-file-size={delta} new-file-size={new}'.format(
        delta=len(delta_file.read_bytes()),
        new=len(test_files['new_fw'].read_bytes())))


def test_generate_delta_no_compression(tmp_path, test_files):
    with pytest.raises(AssertionError):
        generate_delta(
            test_files['orig_fw'],
            test_files['other_fw'],
            tmp_path / 'delta.bin',
            512,
            60
        )


def test_generate_delta_skip_size_check(tmp_path, test_files):
    generate_delta(
        test_files['orig_fw'],
        test_files['other_fw'],
        tmp_path / 'delta.bin',
        512,
        0
    )


def test_generate_delta_skip_threshold(tmp_path, test_files):
    with pytest.raises(AssertionError):
        generate_delta(
            test_files['orig_fw'],
            test_files['new_fw'],
            tmp_path / 'delta.bin',
            512,
            1
        )
