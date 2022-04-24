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

mkdir /work
cd /work

# Clone from shared dir
git clone /io manifest-tool
cd manifest-tool

function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping. No external shared libraries that the wheel depends on"
    else
        auditwheel repair "$wheel" --plat "$PLAT" -w wheelhouse/
        #  Delete original wheel
        rm -f "$wheel"
    fi
}

# Compile wheels to wheelhouse/$PLAT
for PYBIN in /opt/python/cp3*/bin; do
    if [[ $PYBIN == /opt/python/cp35-cp35m/bin ]]; then
        continue
    fi
    if [[ $PYBIN == /opt/python/cp310-cp310/bin ]]; then
        continue
    fi
    echo '------------------------------------------------------------'
    echo "${PYBIN}"
    echo '------------------------------------------------------------'
    "${PYBIN}/pip" wheel . --no-deps -w wheelhouse/$PLAT
done

# Bundle external shared libraries into the wheels
for whl in wheelhouse/$PLAT/*-linux_x86_64.whl; do
    repair_wheel "$whl"
done

for whl in wheelhouse/$PLAT/*-linux_aarch64.whl; do
    repair_wheel "$whl"
done

# Remove wheelhouse/$PLAT if it's empty
if [ -z "$(ls -A wheelhouse/$PLAT)" ]; then
    rm -rf "wheelhouse/$PLAT"
fi

# Install packages and test
for PYBIN in /opt/python/cp3*/bin; do
    if [[ $PYBIN == /opt/python/cp35-cp35m/bin ]]; then
        continue
    fi
    if [[ $PYBIN == /opt/python/cp310-cp310/bin ]]; then
        continue
    fi
    echo '------------------------------------------------------------'
    echo "${PYBIN}"
    echo '------------------------------------------------------------'
    "${PYBIN}/pip" install --prefer-binary -r requirements.txt
    "${PYBIN}/pip" install manifest-tool --no-index -f wheelhouse/
    "${PYBIN}/manifest-tool" --version
    "${PYBIN}/manifest-dev-tool" --version
    "${PYBIN}/manifest-delta-tool" --version

    # Copy to shared dist
    cp -v wheelhouse/* /io/dist/.
done
