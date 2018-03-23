#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016 -*-
# -*- copyright-comment-string: # -*-

import sys, os, asn1ate

from datetime import datetime
from io import StringIO
from asn1ate.parser import parse_asn1
from asn1ate.pyasn1gen import build_semantic_model, generate_pyasn1

def header(source_file, version="<unknown>"):
    lastmod = datetime.fromtimestamp(os.path.getmtime(source_file))

    return """\
#----------------------------------------------------------------------------
#   The confidential and proprietary information contained in this file may
#   only be used by a person authorised under and to the extent permitted
#   by a subsisting licensing agreement from ARM Limited or its affiliates.
#
#          (C) COPYRIGHT 2016 ARM Limited or its affiliates.
#              ALL RIGHTS RESERVED
#
#   This entire notice must be reproduced on all copies of this file
#   and copies of this file may only be made by a person if such person is
#   permitted to do so under the terms of a subsisting license agreement
#   from ARM Limited or its affiliates.
#----------------------------------------------------------------------------
# -*- coding: utf-8 -*-
#
# This file has been generated using asn1ate (v %s) from %r
# Last Modified on %s
""" % (version, source_file, lastmod)

def get_asn_definition(f):
    with open(f, "r") as fh:
        return fh.read().strip()

def generate_pyasn_code(definition):
    parse_tree = parse_asn1(definition)
    modules = build_semantic_model(parse_tree)
    output = StringIO()
    for module in modules:
        generate_pyasn1(module, output)
    return output.getvalue()

def write_code_to_file(code, f, definition_file):
    with open(f, "w") as fh:
        fh.write(header(definition_file))
        fh.write(code)

def main():
    input_asn_definition_file = sys.argv[1]
    output_pyasn_file = sys.argv[2]

    asn_defintion = get_asn_definition(input_asn_definition_file)
    code = generate_pyasn_code(asn_defintion)
    write_code_to_file(code, output_pyasn_file, input_asn_definition_file)

if __name__ == "__main__":
    main()
