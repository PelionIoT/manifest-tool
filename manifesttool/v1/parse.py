# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-

import json, logging, binascii
from manifesttool import codec
from manifesttool.v1 import manifest_definition

# All supported decoders
from pyasn1.codec.der import decoder as der_decoder

LOG = logging.getLogger(__name__)

# Wrapper class with same signature as pyasn1 decoders
class json_decoder(object):
    def decode(self, data, schema):
        return (json.dumps(data),)

def parse(options):
    data = options.input_file.read()
    LOG.debug('Read {} bytes of encoded data. Will try to decode...'.format(len(data)))

    decoded_data = {
        "der": lambda d: codec.bin2obj(d, manifest_definition.SignedResource(), der_decoder, True),
    }[options.encoding](data)
    LOG.debug('Successfully decoded data from {} encoded binary'.format(options.encoding))
    return decoded_data
