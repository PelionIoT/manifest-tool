# ----------------------------------------------------------------------------
# Copyright 2019-2020 Pelion
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
import binascii
import uuid
from pathlib import Path
from typing import Type

import pytest
import yaml
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes

from manifesttool.mtool import mtool, ecdsa_helper
from manifesttool.mtool.actions.create import CreateAction
from manifesttool.mtool.asn1 import ManifestAsnCodecBase, ManifestVersion
from manifesttool.mtool.asn1.v1 import ManifestAsnCodecV1
from tests.conftest import data_generator

SCRIPT_DIR = Path(__file__).resolve().parent
GEN_DIR = SCRIPT_DIR / 'test_data'

FILE_ID = 0


@pytest.mark.parametrize('fw_size', [512, 713, 4096, 100237, 512001])
def test_create_happy_day_full(
        tmp_path_factory,
        fw_size
):
    global FILE_ID
    GEN_DIR.mkdir(exist_ok=True)
    happy_day_data = data_generator(tmp_path_factory, fw_size)
    manifest = None
    for manifest_codec in ManifestVersion.list_codecs():
        input_cfg = {
            'vendor': {
                'domain': 'pelion.com'
            },
            'device': {
                'model-name': 'my-device'
            },
            'priority': 15,
            'payload': {
                'url': '../test_data/{}_f_payload.bin'.format(FILE_ID),
                'file-path': happy_day_data['fw_file'].as_posix(),
                'format': 'raw-binary'
            }
        }
        if issubclass(manifest_codec, ManifestAsnCodecV1):
            version = 100500
            version_file = GEN_DIR / '{}_f_version_{}.txt'.format(
                FILE_ID,
                manifest_codec.get_name())
            version_file.write_text(str(version))
        else:
            component = 'MAIN'
            if (FILE_ID % 2) == 0:
                component = 'TESTCOMP'
                input_cfg['component'] = component
            elif (FILE_ID % 3) == 0:
                input_cfg['component'] = component
            version = '100.500.0'

            version_file = GEN_DIR / '{}_f_version_{}.txt'.format(
                FILE_ID, manifest_codec.get_name())
            version_file.write_text('.'.join(version))

            component_file = GEN_DIR / '{}_f_component.txt'.format(FILE_ID)
            component_file.write_text(component)

        manifest = CreateAction.do_create(
            pem_key_data=happy_day_data['key_file'].read_bytes(),
            input_cfg=input_cfg,
            fw_version=version,
            update_certificate=happy_day_data['certificate_file'],
            asn1_codec_class=manifest_codec
        )
        GEN_DIR.mkdir(exist_ok=True)

        manifest_file = GEN_DIR / '{}_f_manifest_{}.bin'.format(
            FILE_ID, manifest_codec.get_name())
        manifest_file.write_bytes(manifest)

        certificate_file = GEN_DIR / '{}_f_certificate.bin'.format(FILE_ID)
        certificate_file.write_bytes(
            happy_day_data['certificate_file'].read_bytes())

        payload_file = GEN_DIR / '{}_f_payload.bin'.format(FILE_ID)
        payload_file.write_bytes(happy_day_data['fw_file'].read_bytes())

        orig_fw_file = GEN_DIR / '{}_f_curr_fw.bin'.format(FILE_ID)
        orig_fw_file.write_bytes(happy_day_data['fw_file'].read_bytes())

        new_fw_file = GEN_DIR / '{}_f_final_image.bin'.format(FILE_ID)
        new_fw_file.write_bytes(happy_day_data['fw_file'].read_bytes())

        dom = manifest_codec.decode(manifest, None)

        vendor_id_file = GEN_DIR / '{}_f_vendor_id.bin'.format(FILE_ID)
        if manifest_codec.get_name() == 'v3':
            vendor_id_bytes = dom['manifest']['vendor-id']
            class_id_bytes = dom['manifest']['class-id']
        elif manifest_codec.get_name() == 'v1':
            vendor_id_bytes = \
                dom['resource']['resource']['manifest']['vendorId']
            class_id_bytes = dom['resource']['resource']['manifest']['classId']
        else:
            raise AssertionError(
                'invalid manifest version ' + manifest_codec.get_name())
        vendor_id_file.write_bytes(vendor_id_bytes)

        class_id_file = GEN_DIR / '{}_f_class_id.bin'.format(FILE_ID)

        class_id_file.write_bytes(class_id_bytes)

        key_file = GEN_DIR / '{}_f_priv_key.bin'.format(FILE_ID)
        private_key_data = happy_day_data['key_file'].read_bytes()
        key_file.write_bytes(private_key_data)

        public_key = ecdsa_helper.public_key_from_private(private_key_data)
        public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)

        public_key_file = GEN_DIR / '{}_f_pub_key.bin'.format(FILE_ID)
        public_key_file.write_bytes(public_key_bytes)

    FILE_ID += 1

    print(
        'Full manifest in HEX to be viewed on '
        'https://asn1.io/asn1playground/ \n' + binascii.hexlify(
            manifest).decode('utf-8'))


def calc_digest(payload_file):
    hash_ctx = hashes.Hash(hashes.SHA256(), backends.default_backend())
    buf = payload_file.read_bytes()
    hash_ctx.update(buf)
    digest = hash_ctx.finalize()

    return digest.hex()


@pytest.mark.parametrize('fw_size', [512, 713, 4096, 100237, 512001])
def test_create_happy_day_delta(
        tmp_path_factory,
        fw_size
):
    global FILE_ID
    GEN_DIR.mkdir(exist_ok=True)
    happy_day_data = data_generator(tmp_path_factory, fw_size)
    manifest = None
    for manifest_version in ManifestVersion.list_codecs():
        input_cfg = {
            'vendor': {
                'domain': 'pelion.com'
            },
            'device': {
                'model-name': 'my-device'
            },
            'priority': 15,
            'payload': {
                'url': '../test_data/{}_d_payload.bin'.format(FILE_ID),
                'file-path': happy_day_data['delta_file'].as_posix(),
                'format': 'arm-patch-stream'
            },
            'sign-image': 'v1' not in manifest_version.get_name()  # Bool
        }
        if issubclass(manifest_version, ManifestAsnCodecV1):
            version = 100500
            version_file = GEN_DIR / '{}_d_version_{}.txt'.format(
                FILE_ID,
                manifest_version.get_name())
            version_file.write_text(str(version))
        else:
            component = 'MAIN'
            if (FILE_ID % 2) == 0:
                component = 'TESTCOMP'
                input_cfg['component'] = component
            elif (FILE_ID % 3) == 0:
                input_cfg['component'] = component
            version = '100.500.0'

            version_file = GEN_DIR / '{}_d_version_{}.txt'.format(
                FILE_ID,
                manifest_version.get_name())
            version_file.write_text('.'.join(version))

            component_file = GEN_DIR / '{}_d_component.txt'.format(FILE_ID)
            component_file.write_text(component)
        manifest = CreateAction.do_create(
            pem_key_data=happy_day_data['key_file'].read_bytes(),
            input_cfg=input_cfg,
            update_certificate=happy_day_data['certificate_file'],
            fw_version=version,
            asn1_codec_class=manifest_version
        )

        manifest_file = GEN_DIR / '{}_d_manifest_{}.bin'.format(
            FILE_ID, manifest_version.get_name())
        manifest_file.write_bytes(manifest)

        certificate_file = GEN_DIR / '{}_d_certificate.bin'.format(FILE_ID)
        certificate_file.write_bytes(
            happy_day_data['certificate_file'].read_bytes())

        payload_file = GEN_DIR / '{}_d_payload.bin'.format(FILE_ID)
        payload_file.write_bytes(happy_day_data['delta_file'].read_bytes())

        orig_fw_file = GEN_DIR / '{}_d_curr_fw.bin'.format(FILE_ID)
        orig_fw_file.write_bytes(happy_day_data['fw_file'].read_bytes())

        new_fw_file = GEN_DIR / '{}_d_final_image.bin'.format(FILE_ID)
        new_fw_file.write_bytes(happy_day_data['new_fw_file'].read_bytes())

        dom = manifest_version.decode(manifest, None)

        vendor_id_file = GEN_DIR / '{}_d_vendor_id.bin'.format(FILE_ID)
        if manifest_version.get_name() == 'v3':
            vendor_id_bytes = dom['manifest']['vendor-id']
            class_id_bytes = dom['manifest']['class-id']
        elif manifest_version.get_name() == 'v1':
            vendor_id_bytes = \
                dom['resource']['resource']['manifest']['vendorId']
            class_id_bytes = dom['resource']['resource']['manifest']['classId']
        else:
            raise AssertionError(
                'invalid manifest version ' + manifest_version.get_name())
        vendor_id_file.write_bytes(vendor_id_bytes)

        class_id_file = GEN_DIR / '{}_d_class_id.bin'.format(FILE_ID)
        class_id_file.write_bytes(class_id_bytes)

        key_file = GEN_DIR / '{}_d_priv_key.bin'.format(FILE_ID)
        private_key_data = happy_day_data['key_file'].read_bytes()
        key_file.write_bytes(private_key_data)

        public_key = ecdsa_helper.public_key_from_private(private_key_data)
        public_key_bytes = ecdsa_helper.public_key_to_bytes(public_key)

        public_key_file = GEN_DIR / '{}_d_pub_key.bin'.format(FILE_ID)
        public_key_file.write_bytes(public_key_bytes)

    FILE_ID += 1

    print(
        'Delta manifest in HEX to be viewed on '
        'https://asn1.io/asn1playground/ \n' + binascii.hexlify(
            manifest).decode('utf-8'))


@pytest.mark.parametrize('manifest_version', ManifestVersion.list_codecs())
def test_cli_delta(
        happy_day_data, manifest_version: Type[ManifestAsnCodecBase]):
    cli_test_common(happy_day_data, manifest_version, is_delta=True)


@pytest.mark.parametrize('manifest_version', ManifestVersion.list_codecs())
def test_cli_full(
        happy_day_data, manifest_version: Type[ManifestAsnCodecBase]):
    cli_test_common(happy_day_data, manifest_version, is_delta=False)


def cli_test_common(happy_day_data, manifest_version, is_delta):
    tmp_cfg = happy_day_data['tmp_path'] / 'input.yaml'
    output_manifest = happy_day_data['tmp_path'] / 'foo.bin'
    with tmp_cfg.open('wt') as fh:
        yaml.dump(
            {
                'vendor': {
                    'domain': 'pelion.com'
                },
                'device': {
                    'model-name': 'my-device'
                },
                'priority': 15,
                'payload': {
                    'url': 'https://my.server.com/some.file?new=1',
                    'file-path': happy_day_data['delta_file'].as_posix(),
                    'format': 'arm-patch-stream' if is_delta else 'raw-binary'
                }
            },
            fh
        )
    action = 'create'
    if 'v1' in manifest_version.get_name():
        action = 'create-v1'
    cmd = [
        '--debug',
        action,
        '--config', tmp_cfg.as_posix(),
        '--key', happy_day_data['key_file'].as_posix(),
        '--output', output_manifest.as_posix()
    ]
    if manifest_version.get_name() == 'v1':
        cmd.extend(
            [
                '--update-certificate',
                happy_day_data['certificate_file'].as_posix()
            ]
        )
    else:
        cmd.extend(['--fw-version', '100.0.500'])
    assert 0 == mtool.entry_point(cmd)

@pytest.mark.parametrize('manifest_version', ManifestVersion.list_codecs())
def test_create_happy_day_with_ids(
        happy_day_data,
        manifest_version
):
    tmp_cfg = happy_day_data['tmp_path'] / 'input.yaml'
    output_manifest = happy_day_data['tmp_path'] / 'foo.bin'
    with tmp_cfg.open('wt') as fh:
        yaml.dump(
            {
                'vendor': {
                    'vendor-id': uuid.uuid4().hex
                },
                'device': {
                    'class-id': uuid.uuid4().hex
                },
                'priority': 15,
                'payload': {
                    'url': 'https://my.server.com/some.file?new=1',
                    'file-path': happy_day_data['delta_file'].as_posix(),
                    'format': 'arm-patch-stream'
                }
            },
            fh
        )
    action = 'create'
    if 'v1' in manifest_version.get_name():
        action = 'create-v1'
    cmd = [
        '--debug',
        action,
        '--config', tmp_cfg.as_posix(),
        '--key', happy_day_data['key_file'].as_posix(),
        '--output', output_manifest.as_posix()
    ]

    if manifest_version.get_name() == 'v1':
        cmd.extend(
            [
                '--update-certificate',
                happy_day_data['certificate_file'].as_posix()
            ]
        )
    else:
        cmd.extend(['--fw-version', '100.500.8'])

    ret_code = mtool.entry_point(cmd)

    assert ret_code == 0
