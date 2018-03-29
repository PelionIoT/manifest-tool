# -*- coding: utf-8 -*-
# -*- copyright-holder: ARM Limited or its affiliates -*-
# -*- copyright-dates: 2016-2017 -*-
# -*- copyright-comment-string: # -*-
import logging, sys
LOG = logging.getLogger(__name__)

from manifesttool import create
import copy
import time
import tempfile
import os
import os.path
import shutil


MAX_NAME_LEN = 128 # The update API has a maximum name length of 128, but this is not queriable.

tempdirname = None
manifest_file = None

def main_wrapped(options):
    try:
        from mbed_cloud.update import UpdateAPI
        import mbed_cloud.exceptions
    except:
        LOG.critical('manifest-tool update commands require installation of the mbed Cloud SDK:'
                     ' https://github.com/ARMmbed/mbed-cloud-sdk-python')
        return 1
    LOG.debug('Preparing an update on mbed Cloud')
    # upload a firmware
    api = None
    try:
        api = UpdateAPI()
    except ValueError:
        LOG.critical('API key is required to connect to the Update Service. It can be added using manifest-tool init -a'
                     ' <api key> or by manually editing .mbed_cloud_config.json')
        return 1
    if not options.payload_name:
        name = os.path.basename(options.payload.name) + time.strftime('-%Y-%m-%dT%H:%M:%S')
        LOG.warning('Using {} as payload name.'.format(name))
        options.payload_name = name
    if len(options.payload_name) > MAX_NAME_LEN:
        LOG.critical(
            'Payload name is too long. Maximum length is {size}. ("{base}" <- {size}. overflow -> "{overflow}")'.format(
                size=MAX_NAME_LEN, base=options.payload_name[:MAX_NAME_LEN],
                overflow=options.payload_name[MAX_NAME_LEN:]))
        return 1

    if not options.manifest_name:
        name = os.path.basename(options.payload.name) + time.strftime('-%Y-%m-%dT%H:%M:%S-manifest')
        LOG.warning('Using {} as manifest name.'.format(name))
        options.manifest_name = name

    if len(options.manifest_name) > MAX_NAME_LEN:
        LOG.critical(
            'Manifest name is too long. Maximum length is {size}. ("{base}" <- {size}. overflow -> "{overflow}")'.format(
                size=MAX_NAME_LEN, base=options.manifest_name[:MAX_NAME_LEN],
                overflow=options.manifest_name[MAX_NAME_LEN:]))
        return 1

    kwArgs = {}
    if options.payload_description:
        kwArgs['description'] = options.payload_description
    try:
        payload = api.add_firmware_image(
                        name = options.payload_name,
                    datafile = options.payload.name,
                    **kwArgs)
    except mbed_cloud.exceptions.CloudApiException as e:
        # TODO: Produce a better failuer message
        LOG.critical('Upload of payload failed with:')
        print(e)
        return 1

    LOG.info("Created new firmware at {}".format(payload.url))
    options.payload.seek(0)
    # create a manifest
    create_opts = copy.copy(options)
    create_opts.uri = payload.url
    create_opts.payload = options.payload
    if not (hasattr(create_opts, "output_file") and create_opts.output_file):
        global manifest_file
        manifest_file = open(os.path.join(tempdirname,'manifest'),'wb')
        create_opts.output_file = manifest_file

    rc = create.main(create_opts)
    create_opts.output_file.close()
    if rc:
        return rc

    kwArgs = {}
    if options.manifest_description:
        kwArgs['description'] = options.manifest_description

    # upload a manifest
    try:
        manifest = api.add_firmware_manifest(
                        name = options.manifest_name,
                    datafile = create_opts.output_file.name,
                    **kwArgs)
    except mbed_cloud.exceptions.CloudApiException as e:
        # TODO: Produce a better failuer message
        LOG.critical('Upload of manifest failed with:')
        print(e)
        return 1
    LOG.info('Created new manifest at {}'.format(manifest.url))
    return 0

def main(options):
    global tempdirname
    tempdirname = tempfile.mkdtemp()
    RC = main_wrapped(options)
    if manifest_file:
        manifest_file.close()
    shutil.rmtree(tempdirname)
    return RC
