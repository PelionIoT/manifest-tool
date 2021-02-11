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
import contextlib
import os
import uuid
from pathlib import Path
import time

import pytest

from manifesttool import armbsdiff
from manifesttool.delta_tool import delta_tool
from manifesttool.dev_tool import defaults
from manifesttool.dev_tool.actions import init as dev_init

@pytest.fixture(scope="session")
def happy_day_data(tmp_path_factory):
    yield data_generator(tmp_path_factory, size=512)

@pytest.fixture
def timeless(monkeypatch):

    timeless.cur_time = time.time()

    def sleep_mock(seconds):
        timeless.cur_time += seconds

    def time_mock() -> float:
        return timeless.cur_time

    monkeypatch.setattr(time, 'sleep', sleep_mock)
    monkeypatch.setattr(time, 'time', time_mock)

def data_generator(tmp_path_factory, size):
    tmp_path = tmp_path_factory.mktemp("data")
    key_file = tmp_path / 'dev.key.pem'
    certificate_file = tmp_path / 'dev.cert.der'
    dev_init.generate_credentials(
        key_file=key_file,
        certificate_file=certificate_file,
        cred_valid_time=8
    )
    bsdiff_version = armbsdiff.get_version().encode('utf-8')
    fw_file = tmp_path / 'fw.bin'
    fw_data = bsdiff_version + os.urandom(size)
    fw_file.write_bytes(fw_data)
    new_fw_file = tmp_path / 'new_fw.bin'
    new_fw_data = fw_data + os.urandom(512)
    new_fw_file.write_bytes(new_fw_data)
    delta_file = tmp_path / 'delta.bin'
    delta_tool.generate_delta(
        orig_fw=fw_file,
        new_fw=new_fw_file,
        output_delta_file=delta_file,
        block_size=512,
        threshold=60
    )

    class_id = uuid.uuid4()
    vendor_id = uuid.uuid4()

    dev_cfg = tmp_path / 'dev.cfg.yaml'
    dev_init.generate_developer_config(
        key_file=key_file,
        certificate_file=certificate_file,
        config=dev_cfg,
        class_id=class_id,
        vendor_id=vendor_id
    )

    api_config_path = tmp_path / 'dev.cloud_cfg.yaml'
    dev_init.generate_service_config(
        api_key='sdsdadadadsdadasdadsadasdas',
        api_url=defaults.API_GW,
        api_config_path=api_config_path
    )

    return {
        'fw_file': fw_file,
        'new_fw_file': new_fw_file,
        'delta_file': delta_file,
        'key_file': key_file,
        'certificate_file': certificate_file,
        'tmp_path': tmp_path,
        'dev_cfg': dev_cfg,
        'api_config_path': api_config_path
    }

@contextlib.contextmanager
def working_directory(path: Path):
    current = Path.cwd()
    os.chdir(path.as_posix())
    try:
        yield
    finally:
        os.chdir(current.as_posix())
