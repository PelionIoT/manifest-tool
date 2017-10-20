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

from manifesttool.v2 import cms_signed_data_definition
from manifesttool.v2 import create
from manifesttool.v2 import verify
from manifesttool import utils
from manifesttool import codec
from manifesttool import defaults
# All supported decoders
from pyasn1.codec.der import decoder as der_decoder

import os
import json
import logging
LOG = logging.getLogger(__name__)

def sign(options, manifestInput, parsedCMS, manifest):
    signerInfo = create.create_cms_signer_info(options, manifestInput, manifest)
    if not signerInfo:
        return None
    parsedCMS['content']['signedData']['signerInfos'].append(signerInfo)
    return parsedCMS

def parseCMS(options, data):
    LOG.debug('Read {} bytes of encoded data. Will try to decode...'.format(len(data)))

    decoded_CMS = {
        "der": lambda d: codec.bin2obj_native(d, cms_signed_data_definition.ContentInfo(), der_decoder),
    }[options.encoding](data)
    return decoded_CMS

def main(options):
    if hasattr(options, 'manifest') and options.manifest:
        options.input_file = options.manifest
    if not hasattr(options, 'input_file') or not options.input_file:
        return 1
    # Verify the manifest
    rc = verify.main(options)
    if rc != 0:
        return rc

    # Parse the CMS wrapper
    options.input_file.seek(0)
    data = bytes(options.input_file.read())

    decoded_CMS = {
        "der": lambda d: codec.bin2obj_native(d, cms_signed_data_definition.ContentInfo(), der_decoder),
    }[options.encoding](data)

    decoded_CMS = parseCMS(options, data)
    if not decoded_CMS:
        return 1

    # Extract the octet stream
    manifest = decoded_CMS['content']['signedData']['encapContentInfo']['eContent']

    manifestInput = {}

    if hasattr(options, 'certificate') and options.certificate:
        manifestInput['certificates'] = [{'file':options.certificate.name}]
    else:
        try:
            if os.path.exists(defaults.config):
                with open(defaults.config) as f:
                    manifestInput.update(json.load(f))
        except ValueError as e:
            LOG.critical("JSON Decode Error: {}".format(e))
            return 1


    # Make a new signature block
    new_CMS = sign(options, manifestInput, decoded_CMS, manifest)
    if not new_CMS:
        return 1

    # re-encode the CMS wrapper
    LOG.debug('Encoding Content Info')
    encoded_contentInfo = utils.encode(new_CMS, options, cms_signed_data_definition.ContentInfo())
    create.write_result(encoded_contentInfo, options)
    return 0
