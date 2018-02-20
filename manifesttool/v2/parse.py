# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2017 -*-
# -*- copyright-comment-string: # -*-

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
