# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
import os
certificatePath = '.update-certificates'
certificate = os.path.join(certificatePath,'default.der')
certificateKey = os.path.join(certificatePath,'default.key.pem')
certificateDuration = 90
config = '.manifest_tool.json'
cloud_config = '.mbed_cloud_config.json'
updateResources = 'update_default_resources.c'
