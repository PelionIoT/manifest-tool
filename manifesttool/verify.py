# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
import json, logging, binascii
from builtins import bytes
from manifesttool.v1.verify import main as verify_v1
from manifesttool.v2.verify import main as verify_v2

LOG = logging.getLogger(__name__)

def skipAhead(code):
    rc = 0
    if code == 0x81:
        rc = 1
    if code == 0x82:
        rc = 2
    if code == 0x83:
        rc = 3
    if code == 0x83:
        rc = 4
    return rc

def main(options):
    LOG.debug("Attempting to determine manifest version...")
    # 32 bytes is currently sufficient to detect the manifest type.
    headerData = bytes(options.input_file.read(32))
    options.input_file.seek(0)
    # In both cases, the manifest starts with a DER SEQUENCE tag.
    if headerData[0] != 0x30:
        LOG.critical("input file is not a manifest.")
        return 1
    # skip past the length
    pos = 2 + skipAhead(headerData[1])

    version = None
    # For version 1, the first object in the SEQUENCE should be another SEQUENCE
    if headerData[pos] == 0x30:
        version = 1
    # For version 2+, a CMS wrapper is used, so the tag should be an OID tag
    if headerData[pos] == 0x06:
        version = 2

    if version == None:
        LOG.critical("No recognized manifest format found.")
        return 1

    # For now, we will assume that 2+ means 2.
    parser = {
        1 : verify_v1,
        2 : verify_v2
    }.get(version, None)
    if not parser:
        LOG.critical("Unrecognized manifest version.")
        return 1
    return parser(options)
