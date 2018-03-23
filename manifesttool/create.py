# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
from manifesttool.v1.create import main as create_v1

def main(options):
    create = {
        '1' : create_v1
    }.get(options.manifest_version)
    return create(options)
