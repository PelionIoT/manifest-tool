# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2017 ARM Limited or its affiliates
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
import logging
import sys
LOG = logging.getLogger(__name__)

from manifesttool import prepare
from manifesttool import update_device as device

def main(options):
    if (hasattr(options,"psk") and options.psk) or (hasattr(options,"mac") and options.mac):
        LOG.critical('manifest-tool update commands are not currently enabled for PSK/MAC authentication.')
        return 1
    try:
        from mbed_cloud.update import UpdateAPI
        from mbed_cloud import __version__ as mc_version
        if mc_version < "1.2.6":
            LOG.warning("Your version of mbed-cloud-sdk may need updating: https://github.com/ARMmbed/mbed-cloud-sdk-python")
    except:
        LOG.critical('manifest-tool update commands require installation of the Mbed Cloud SDK: https://github.com/ARMmbed/mbed-cloud-sdk-python')
        return 1
    return {
        "prepare" : prepare.main,
        "device" : device.main
    }[options.update_action](options)
