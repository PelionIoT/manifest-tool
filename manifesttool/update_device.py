# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

import logging, sys
LOG = logging.getLogger(__name__)

from manifesttool import create
from urllib3.exceptions import MaxRetryError
import copy
import time
import tempfile
import os
import os.path
import shutil

STOP_STATES = {'autostopped',
               'conflict',
               'expired',
               'manifestremoved',
               'quotaallocationfailed',
               'userstopped'}

MAX_NAME_LEN = 128 # The update API has a maximum name length of 128, but this is not queriable.

def main(options):
    try:
        # import mbed_cloud.update
        from mbed_cloud.update import UpdateAPI
        # from mbed_cloud.device_directory import DeviceDirectoryAPI
        import mbed_cloud.exceptions
    except:
        LOG.critical('manifest-tool update commands require installation of the Mbed Cloud SDK:'
                     ' https://github.com/ARMmbed/mbed-cloud-sdk-python')
        return 1

    LOG.debug('Preparing an update on Mbed Cloud')
    # upload a firmware
    api = None
    # dd_api = None
    try:
        # If set use api key set in manifest-tool update.
        if hasattr(options, 'api_key') and options.api_key:
            tempKey = options.api_key
            config = {'api_key': tempKey}
            api = UpdateAPI(config)
        # Otherwise use API key set in manifest-tool init
        else: api = UpdateAPI()
        # dd_api = DeviceDirectoryAPI()

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
    campaign_name = options.payload.name + time.strftime('-%Y-%m-%dT%H:%M:%S-campaign')
    if len(campaign_name) > MAX_NAME_LEN:
        LOG.critical(
            'Campaign name is too long. Maximum length is {size}. ("{base}" <- {size}. overflow -> "{overflow}")'.format(
                size=MAX_NAME_LEN, base=campaign_name[:MAX_NAME_LEN],
                overflow=campaign_name[MAX_NAME_LEN:]))
        return 1
    query_name = options.payload.name + time.strftime('-%Y-%m-%dT%H:%M:%S-filter')
    if len(query_name) > MAX_NAME_LEN:
        LOG.critical(
            'Filter name is too long. Maximum length is {size}. ("{base}" <- {size}. overflow -> "{overflow}")'.format(
                size=MAX_NAME_LEN, base=query_name[:MAX_NAME_LEN],
                overflow=query_name[MAX_NAME_LEN:]))
        return 1


    payload = None
    manifest = None
    campaign = None
    RC = 0
    handled = False
    manifest_file = None
    tempdirname = tempfile.mkdtemp()
    try:
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
            handled = True
            LOG.critical('Check API server URL set in manifest-tool init step')
            raise e
        except MaxRetryError as e:
            LOG.critical('Upload of payload failed with:')
            print(e)
            handled=True
            LOG.critical('Failed to establish connection to URL. Check validity of API server URL set in manifest-tool init step.')
            raise e

        LOG.info("Created new firmware at {}".format(payload.url))
        options.payload.seek(0)
        # create a manifest
        create_opts = copy.copy(options)
        create_opts.uri = payload.url
        create_opts.payload = options.payload
        if not (hasattr(create_opts, "output_file") and create_opts.output_file):
            try:
                manifest_file = open(os.path.join(tempdirname,'manifest'),'wb')
                LOG.info("Created temporary manifest file at {}".format(manifest_file.name))
                create_opts.output_file = manifest_file
            except IOError as e:
                LOG.critical("Failed to create temporary manifest file with:")
                print(e)
                LOG.critical("Try using '-o' to output a manifest file at a writable location.")
                handled = True
                raise e
        try:
            rc = create.main(create_opts)
        except IOError as e:
            LOG.critical("Failed to create manifest with:")
            print(e)
            handled = True
            raise e

        if rc:
            return rc

        kwArgs = {}
        if options.manifest_description:
            kwArgs['description'] = options.manifest_description

        manifest_path = create_opts.output_file.name
        create_opts.output_file.close()
        # upload a manifest
        try:
            manifest = api.add_firmware_manifest(
                            name = options.manifest_name,
                        datafile = manifest_path,
                        **kwArgs)
        except mbed_cloud.exceptions.CloudApiException as e:
            # TODO: Produce a better failure message
            LOG.critical('Upload of manifest failed with:')
            print(e)
            LOG.critical("Try using '-o' to output a manifest file at a writable location.")
            handled = True
            raise e

        LOG.info('Created new manifest at {}'.format(manifest.url))
        LOG.info('Manifest ID: {}'.format(manifest.id))

        try:
            campaign = api.add_campaign(
                name = campaign_name,
                manifest_id = manifest.id,
                device_filter = {'id': { '$eq': options.device_id }},
            )
        except mbed_cloud.exceptions.CloudApiException as e:
            LOG.critical('Campaign creation failed with:')
            print(e)
            handled = True
            raise e

        LOG.info('Campaign successfully created. Current state: %r' % (campaign.state))
        LOG.info('Campaign successfully created. Filter result: %r' % (campaign.device_filter))

        LOG.info("Starting the update campign...")

        # By default a new campaign is created with the 'draft' status. We can manually start it.
        try:
            new_campaign = api.start_campaign(campaign)
            new_campaign = None
        except mbed_cloud.exceptions.CloudApiException as e:
            LOG.critical('Starting campaign failed with:')
            print(e)
            handled = True
            raise e

        LOG.info("Campaign successfully started. Current state: %r. Checking updates.." % (campaign.state))
        oldstate = api.get_campaign(campaign.id).state
        LOG.info("Current state: %r" % (oldstate))
        timeout = options.timeout
        while timeout != 0:
            c = api.get_campaign(campaign.id)
            if oldstate != c.state:
                LOG.info("Current state: %r" % (c.state))
                oldstate = c.state
            if c.state in STOP_STATES:
                LOG.info("Finished in state: %r" % (c.state))
                break
            time.sleep(1)
            if timeout > 0:
                timeout -= 1
        if timeout == 0:
            LOG.critical("Campaign timed out")
            RC = 1

    except KeyboardInterrupt as e:
        LOG.critical('User Aborted... Cleaning up.')
        RC = 1
    except:
        if not handled:
            LOG.critical('Unhandled Exception:')
            import traceback
            traceback.print_exc(file=sys.stdout)
        RC = 1
    finally:
        # cleanup
        if manifest_file:
            manifest_file.close()
        shutil.rmtree(tempdirname)
        if not options.no_cleanup:
            LOG.info("** Deleting update campaign and manifest **")
            try:
                if campaign and campaign.id:
                    api.delete_campaign(campaign.id)
                if manifest and manifest.id:
                    api.delete_firmware_manifest(manifest.id)
                if payload and payload.id:
                    api.delete_firmware_image(payload.id)
                # dd_api.delete_query(new_query.id)
            except mbed_cloud.exceptions.CloudApiException as e:
                LOG.critical('Cleanup of campaign failed with:')
                print(e)
                RC = 1
    return RC
