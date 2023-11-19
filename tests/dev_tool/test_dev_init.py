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

import yaml
import pytest

from manifesttool.delta_tool.delta_tool import digest_file
from manifesttool.dev_tool import dev_tool, defaults
from tests.conftest import working_directory
from tests.conftest import data_generator


def test_cli_happy_day(tmp_path):
    c_source = tmp_path / "update_default_resources.c"
    cache_dir = tmp_path / defaults.BASE_PATH.as_posix()
    dev_cfg = cache_dir / defaults.DEV_CFG
    cert = cache_dir / defaults.UPDATE_PUBLIC_KEY_CERT
    key = cache_dir / defaults.UPDATE_PRIVATE_KEY
    api_cfg = cache_dir / defaults.CLOUD_CFG

    dummy_access_key = "456321789541515"
    dummy_api_url = "https://i.am.tired.of.writing.tests.com"

    cmd = ["--debug", "init"]

    with working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd)

    assert not api_cfg.is_file()

    dev_cfg_digest = digest_file(dev_cfg)
    c_source_digest = digest_file(c_source)
    cert_digest = digest_file(cert)
    key_digest = digest_file(key)

    cmd = [
        "init",
        "--access-key",
        dummy_access_key,
        "--api-url",
        dummy_api_url,
    ]

    with working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(
            cmd + ["--api-url", "https://some.url.izumanetworks.com"]
        )

    assert c_source_digest != digest_file(c_source)
    assert cert_digest != digest_file(cert)
    assert key_digest != digest_file(key)
    assert dev_cfg_digest != digest_file(dev_cfg)
    assert api_cfg.is_file()

    with working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd)

    assert c_source_digest != digest_file(c_source)
    assert cert_digest != digest_file(cert)
    assert key_digest != digest_file(key)
    assert dev_cfg_digest != digest_file(dev_cfg)

    with api_cfg.open("rb") as fh:
        api_cfg_data = yaml.safe_load(fh)
    assert dummy_access_key == api_cfg_data["access_key"]
    assert dummy_api_url == api_cfg_data["host"]


def test_cli_import_cred(tmp_path, happy_day_data):
    cert = happy_day_data["certificate_file"]
    key = happy_day_data["key_file"]

    # Check that the parameters --key and --update-certificate
    # are coming together
    cmd = ["init", "--key", key]

    # Expect an exception if only --signing-tool parameter is provided
    # The exception is error 2, coming from parse.error() function
    # https://docs.python.org/3/library/argparse.html
    # ArgumentParser.error(message)
    # This method prints a usage message including the message to the standard
    # error and terminates the program with a status code of 2.
    expected_error_code = 2

    with working_directory(tmp_path):
        with pytest.raises(SystemExit) as e:
            dev_tool.entry_point(cmd)
        assert e.value.code == expected_error_code

    cmd = ["init", "--update-certificate", cert.as_posix()]

    with working_directory(tmp_path):
        with pytest.raises(SystemExit) as e:
            dev_tool.entry_point(cmd)
        assert e.value.code == expected_error_code

    cmd = [
        "init",
        "--key",
        key,
        "--update-certificate",
        cert.as_posix(),
    ]

    # Expect no exception if both parameters are provided
    with working_directory(tmp_path):
        assert 0 == dev_tool.entry_point(cmd)


def test_cli_signing_tool(tmp_path_factory):
    happy_day_data = data_generator(
        tmp_path_factory, size=512, signing_tool=True
    )
    cert = happy_day_data["certificate_file"]
    key = happy_day_data["key_file"]
    signing_tool = happy_day_data["signing_tool"].as_posix()

    # Expect an exception if only --signing-tool parameter is provided
    # The exception is error 2, coming from parse.error() function
    # https://docs.python.org/3/library/argparse.html
    # ArgumentParser.error(message)
    # This method prints a usage message including the message to the standard
    # error and terminates the program with a status code of 2.
    expected_error_code = 2

    # Check that the parameters --signing-tool is coming
    # together with certificate and private key
    cmd = ["init", "--signing-tool", signing_tool]

    with working_directory(happy_day_data["tmp_path"]):
        with pytest.raises(SystemExit) as e:
            dev_tool.entry_point(cmd)
        assert e.value.code == expected_error_code

    cmd = [
        "init",
        "--signing-tool",
        signing_tool,
        "--key",
        key,
    ]

    with working_directory(happy_day_data["tmp_path"]):
        with pytest.raises(SystemExit) as e:
            dev_tool.entry_point(cmd)
        assert e.value.code == expected_error_code

    cmd = [
        "init",
        "--signing-tool",
        signing_tool,
        "--update-certificate",
        cert.as_posix(),
    ]

    with working_directory(happy_day_data["tmp_path"]):
        with pytest.raises(SystemExit) as e:
            dev_tool.entry_point(cmd)
        assert e.value.code == expected_error_code

    cmd = [
        "init",
        "--signing-tool",
        signing_tool,
        "--key",
        key,
        "--update-certificate",
        cert.as_posix(),
    ]

    # Expect no exception if all 3 parameters are provided
    with working_directory(happy_day_data["tmp_path"]):
        assert 0 == dev_tool.entry_point(cmd)


def test_cli_signing_tool_with_key_id(tmp_path_factory):
    happy_day_data = data_generator(
        tmp_path_factory, size=512, signing_tool=True
    )
    cert = happy_day_data["certificate_file"]
    key_id = "123"
    signing_tool = happy_day_data["signing_tool"].as_posix()

    cmd = [
        "init",
        "--signing-tool",
        signing_tool,
        "--key",
        key_id,
        "--update-certificate",
        cert.as_posix(),
    ]

    # The key parameter can be also an identifier whe signing-tool is used
    with working_directory(happy_day_data["tmp_path"]):
        assert 0 == dev_tool.entry_point(cmd)

    cmd = [
        "init",
        "--key",
        key_id,
        "--update-certificate",
        cert.as_posix(),
    ]

    # When signing-tool isn't used, the key must be an existing file
    with working_directory(happy_day_data["tmp_path"]):
        assert 1 == dev_tool.entry_point(cmd)
