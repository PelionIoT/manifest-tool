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
from manifesttool.v1.create import main as create_v1
import os
import sys
import json
from manifesttool import defaults
import logging, sys
LOG = logging.getLogger(__name__)

def main(options):

    # Read options from manifest input file/
    # if (options.input_file.isatty()):
    #     LOG.info("Reading data from from active TTY... Terminate input with ^D")
    manifestInput = {
        'applyImmediately' : True
    }

    try:
        if os.path.exists(defaults.config):
            with open(defaults.config) as f:
                manifestInput.update(json.load(f))
        if not options.input_file.isatty():
            content = options.input_file.read()
            if content and len(content) >= 2: #The minimum size of a JSON file is 2: '{}'
                manifestInput.update(json.loads(content))
    except ValueError as e:
        LOG.critical("JSON Decode Error: {}".format(e))
        sys.exit(1)

    create = {
        '1' : create_v1
    }.get(options.manifest_version)

    return create(options, manifestInput)
