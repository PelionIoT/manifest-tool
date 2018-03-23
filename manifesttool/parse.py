# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
import json, logging
from builtins import bytes
from manifesttool.v1.parse import parse as parser_v1

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

def parse(options):
    LOG.debug("Attempting to determine manifest version...")
    # 32 bytes is currently sufficient to detect the manifest type.
    headerData = bytes(options.input_file.read(32))
    options.input_file.seek(0)
    # In both cases, the manifest starts with a DER SEQUENCE tag.
    if headerData[0] != 0x30:
        LOG.critical("input file is not a manifest.")
        return None, None
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
        return None, None
    # For now, we will assume that 2+ means 2.
    parser = {
        1 : parser_v1
    }.get(version, None)
    if not parser:
        LOG.critical("Unrecognized manifest version.")
        return None, None
    return parser(options)


def main(options):
    decoded_manifest = parse(options)
    if not decoded_manifest:
        return 1

    indent = None if not options.pretty_json else 4

    # Write to output buffer/file
    options.output_file.write(str.encode(json.dumps(decoded_manifest, indent = indent)))

    # If we're writing to TTY, add a helpful newline
    if options.output_file.isatty():
        options.output_file.write(b'\n')
