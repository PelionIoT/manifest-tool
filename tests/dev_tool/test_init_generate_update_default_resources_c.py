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
import uuid

from manifesttool.dev_tool.actions.init import generate_credentials
from manifesttool.dev_tool.actions.init import (
    generate_update_default_resources_c,
)


def test_generate_update_default_resources_c_happy_day(tmp_path):
    key_file = tmp_path / "dev.key.pem"
    certificate_file = tmp_path / "dev.cert.der"
    generate_credentials(
        key_file=key_file, cert_file=certificate_file, cred_valid_time=8
    )
    c_source = tmp_path / "my_source.c"
    vendor_id = uuid.uuid4()
    class_id = uuid.uuid4()

    generate_update_default_resources_c(
        c_source=c_source,
        vendor_id=vendor_id,
        class_id=class_id,
        private_key_file=key_file,
        cert_file=certificate_file,
    )
    assert c_source.is_file()
    gen_data = c_source.read_text()
    assert "arm_uc_vendor_id" in gen_data
    assert "arm_uc_class_id" in gen_data
    assert "arm_uc_default_certificate" in gen_data
