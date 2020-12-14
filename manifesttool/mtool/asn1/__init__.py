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
import argparse
import collections
from typing import Type

from manifesttool.mtool.asn1 import v3, v1
from manifesttool.mtool.asn1.manifest_codec import ManifestAsnCodecBase


class ManifestVersion:
    VERSIONS = collections.OrderedDict(
        [
            (v3.ManifestAsnCodecV3.get_name(), v3.ManifestAsnCodecV3),
            (v1.ManifestAsnCodecV1.get_name(), v1.ManifestAsnCodecV1)
        ]
    )

    @classmethod
    def list_names(cls):
        return cls.VERSIONS.keys()

    @classmethod
    def list_codecs(cls):
        return cls.VERSIONS.values()

    @classmethod
    def from_string(cls, _str: str) -> Type[ManifestAsnCodecBase]:
        return cls.VERSIONS[_str]

    @classmethod
    def get_default(cls) -> Type[ManifestAsnCodecBase]:
        return next(iter(cls.VERSIONS.values()))

# pylint: disable=too-few-public-methods
class StoreManifestVersion(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective = values
        try:
            setattr(namespace, self.dest,
                    ManifestVersion.from_string(prospective))
        except KeyError as ex:
            raise argparse.ArgumentTypeError(
                'invalid manifest schema version') from ex
