#!/bin/bash -e
# ----------------------------------------------------------------------------
# Copyright 2019-2021 Pelion
# Copyright (c) 2023 Izuma Networks
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


DELTA_TOOL_DIR=${1:?"missing delta-tool directory path"}
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

declare -a BSDIFF_FILES=(
    "$DELTA_TOOL_DIR/bsdiff/bsdiff.c"
    "$DELTA_TOOL_DIR/bsdiff/bsdiff.h"
    "$DELTA_TOOL_DIR/bsdiff/bsdiff_helper.c"
    "$DELTA_TOOL_DIR/bsdiff/bsdiff_helper.h"
    "$DELTA_TOOL_DIR/bsdiff/common.h"
    "$DELTA_TOOL_DIR/bsdiff/lz4.c"
    "$DELTA_TOOL_DIR/bsdiff/lz4.h"
    "$DELTA_TOOL_DIR/bsdiff/varint.c"
    "$DELTA_TOOL_DIR/bsdiff/varint.h"
)

for file in "${BSDIFF_FILES[@]}"
do
   cp -v "$file" "$SCRIPT_DIR"
done

echo "Imported from delta-tool at hash: $(git -C "$DELTA_TOOL_DIR" rev-parse HEAD)" > "$SCRIPT_DIR"/import_ref.txt