# ----------------------------------------------------------------------------
# Copyright 2019-2020 Pelion
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
from pathlib import Path

import yaml
BASE_PATH = Path('.manifest-dev-tool')
UPDATE_PUBLIC_KEY_CERT = 'dev.cert.der'
UPDATE_PRIVATE_KEY = 'dev.key.pem'
DEV_CFG = 'dev.cfg.yaml'
UPDATE_RESOURCE_C = 'update_default_resources.c'
CLOUD_CFG = 'dev.cloud_cfg.yaml'
DEV_README = 'README.txt'
API_GW = 'https://api.us-east-1.mbedcloud.com'
UPDATE_VERSION = 'update.version.yaml'

PELION_GW_PATH = Path.home() / '.pelion-dev-presets.yaml'
PELION_GW = None
if PELION_GW_PATH.is_file():
    with PELION_GW_PATH.open('rb') as fh:
        PELION_GW = yaml.safe_load(fh)
