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

import json, logging
import binascii
from manifesttool import codec
from manifesttool.v2 import cms_signed_data_definition
from manifesttool.v2 import manifest_definition
# All supported decoders
from pyasn1.codec.der import decoder as der_decoder
import pyasn1
# pyasn1.debug.setLogger(pyasn1.debug.Debug("all"))

LOG = logging.getLogger(__name__)

# Wrapper class with same signature as pyasn1 decoders
class json_decoder(object):
    def decode(self, data, schema):
        return (json.dumps(data),)

def parse(options):
    data = bytes(options.input_file.read())
    LOG.debug('Read {} bytes of encoded data. Will try to decode...'.format(len(data)))

    decoded_CMS = {
        "der": lambda d: codec.bin2obj_native(d, cms_signed_data_definition.ContentInfo(), der_decoder),
    }[options.encoding](data)

    encoded_manifest = decoded_CMS['content']['signedData']['encapContentInfo']['eContent']

    decoded_manifest = {
        "der": lambda d: codec.bin2obj(d, manifest_definition.Manifest(), der_decoder),
    }[options.encoding](encoded_manifest)
    enumValues = manifest_definition.Manifest().getComponentType()['manifestVersion'].getType().getNamedValues()
    decoded_manifest['manifestVersion'] = enumValues.getValue(decoded_manifest['manifestVersion'])
    LOG.debug('Successfully decoded data from {} encoded binary'.format(options.encoding))
    return decoded_manifest
