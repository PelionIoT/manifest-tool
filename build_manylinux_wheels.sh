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
rm -rf dist/*

PLAT=manylinux1_x86_64     && docker run --rm -e PLAT=$PLAT -v `pwd`:/io quay.io/pypa/$PLAT /io/build_manylinux_wheels_entry_point.sh |& tee $PLAT.log &

PLAT=manylinux2010_x86_64  && docker run --rm -e PLAT=$PLAT -v `pwd`:/io quay.io/pypa/$PLAT /io/build_manylinux_wheels_entry_point.sh |& tee $PLAT.log &

PLAT=manylinux2014_x86_64  && docker run --rm -e PLAT=$PLAT -v `pwd`:/io quay.io/pypa/$PLAT /io/build_manylinux_wheels_entry_point.sh |& tee $PLAT.log &

PLAT=manylinux_2_24_x86_64 && docker run --rm -e PLAT=$PLAT -v `pwd`:/io quay.io/pypa/$PLAT /io/build_manylinux_wheels_entry_point.sh |& tee $PLAT.log &

docker run --rm --privileged tonistiigi/binfmt:latest --install all &

PLAT=manylinux2014_aarch64 && docker run --rm -e PLAT=$PLAT -v `pwd`:/io quay.io/pypa/$PLAT /io/build_manylinux_wheels_entry_point.sh |& tee $PLAT.log &

wait

sudo chown -R $USER:$USER dist/
