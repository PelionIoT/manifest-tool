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

from setuptools import setup, find_packages
import pip
import manifesttool
import os


try: # for pip >= 10
    from pip._internal.req import parse_requirements
    from pip._internal.download import PipSession
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements
    from pip.download import PipSession

install_reqs = parse_requirements('requirements.txt', session=PipSession())
reqs = [str(r.req) for r in install_reqs]

if os.name == 'nt':
    entry_points={
        "console_scripts": [
            "manifest-tool=manifesttool.clidriver:main",
        ],
    }
    scripts = []
else:
    platform_deps = []
    # entry points are nice, but add ~100ms to startup time with all the
    # pkg_resources infrastructure, so we use scripts= instead on unix-y
    # platforms:
    scripts = ['bin/manifest-tool', ]
    entry_points = {}

setup(
    name='manifest-tool',
    version=manifesttool.__version__,
    description='Tool/lib to create and parse manifests',
    long_description=open("README.md").read(),
    url='https://github.com/ARMmbed/update-client-manifest-manager/manifestTool',
    author='Brendan Moran',
    author_email='brendan.moran@arm.com',
    packages=find_packages(exclude=['tests*']),
    zip_safe=False,
    scripts=scripts,
    entry_points=entry_points,
    install_requires=reqs
)
