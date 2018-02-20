# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2017 -*-
# -*- copyright-comment-string: # -*-
import logging
import sys
LOG = logging.getLogger(__name__)

from manifesttool import prepare
from manifesttool import update_device as device

def main(options):
    try:
        from mbed_cloud.update import UpdateAPI
    except:
        LOG.critical('manifest-tool update commands require installation of the mbed Cloud SDK: https://github.com/ARMmbed/mbed-cloud-sdk-python')
        return 1
    return {
        "prepare" : prepare.main,
        "device" : device.main
    }[options.update_action](options)
