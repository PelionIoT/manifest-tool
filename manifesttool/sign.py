# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-

from manifesttool.v1.sign import main as sign_v1
from manifesttool.utils import detect_version

def main(options):
    version = detect_version(options.manifest)
    if not version:
        return 1
    sign = {
        '1' : sign_v1
    }.get(version)
    if not sign:
        return 1
    return sign(options)
