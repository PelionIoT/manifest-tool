# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Limited or its affiliates
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
certificatePath = '.update-certificates'
certificate = os.path.join(certificatePath,'default.der')
certificateKey = os.path.join(certificatePath,'default.key.pem')
certificateDuration = 90
pskMasterKey = os.path.join(certificatePath,'default.master.psk')
config = '.manifest_tool.json'
cloud_config = '.mbed_cloud_config.json'
updateResources = 'update_default_resources.c'
