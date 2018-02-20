# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
from manifesttool.v1.create import main as create_v1
from manifesttool.v2.create import main as create_v2

def main(options):
    create = {
        '1' : create_v1,
        '2' : create_v2
    }.get(options.manifest_version)
    return create(options)
