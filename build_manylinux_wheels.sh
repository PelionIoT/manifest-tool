#!/bin/bash
# ----------------------------------------------------------------------------
# Copyright 2020-2021 Pelion
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

set -e -u -x

mkdir -p dist

# work in parallel
docker run --rm -e PLAT=manylinux1_x86_64     -v `pwd`:/io quay.io/pypa/manylinux1_x86_64     /io/build_manylinux_wheels_entry_point.sh &
docker run --rm -e PLAT=manylinux2010_x86_64  -v `pwd`:/io quay.io/pypa/manylinux2010_x86_64  /io/build_manylinux_wheels_entry_point.sh &
docker run --rm -e PLAT=manylinux2014_x86_64  -v `pwd`:/io quay.io/pypa/manylinux2014_x86_64  /io/build_manylinux_wheels_entry_point.sh &

wait

sudo chown -R $USERNAME:$USERNAME dist/
