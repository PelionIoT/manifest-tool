# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
# Copyright (c) 2022-2023 Izuma Networks
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
"""Setup of manifest tool."""
from setuptools import setup, find_packages, Extension

import manifesttool

armbsdiff = Extension(
    "manifesttool.armbsdiff",
    sources=[
        "bsdiff/bsdiff.c",
        "bsdiff/bsdiff_helper.c",
        "bsdiff/bsdiff_python.c",
        "bsdiff/lz4.c",
        "bsdiff/varint.c",
    ],
    include_dirs=["bsdiff"],
    define_macros=[("LZ4_MEMORY_USAGE", "10")],
    extra_compile_args=["--std=c99", "-O3"],
)

with open("requirements.txt", "rt") as fh:
    tool_requirements = fh.readlines()

setup(
    name="manifest-tool",
    version=manifesttool.__version__,
    description="Tool/lib to create and parse manifests",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/PelionIoT/manifest-tool",
    author="Izuma Networks",
    author_email="opensource@izumanetworks.com",
    license="Apache 2.0",
    packages=find_packages(exclude=["tests"]),
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "manifest-tool=manifesttool.mtool.mtool:entry_point",
            "manifest-dev-tool=manifesttool.dev_tool.dev_tool:entry_point",
            "manifest-delta-tool=manifesttool.delta_tool.delta_tool:entry_point",  # noqa: E501
            "manifest-package-tool=manifesttool.package_tool.package_tool:entry_point",  # noqa: E501
        ],
    },
    python_requires=">=3.7.0",
    include_package_data=True,
    install_requires=tool_requirements,
    ext_modules=[armbsdiff],
)
