// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifndef DELTA_TOOL_INTERNAL_BSDIFF_BSDIFF_HELPER_H_
#define DELTA_TOOL_INTERNAL_BSDIFF_BSDIFF_HELPER_H_

void deliver_error(const char *msg);

int do_diff(
        const char* old_fw_img,
        const char* new_fw_img,
        const char* delta_file,
        int64_t max_frame_size
);


const char *bsdiff_get_version(void);



#endif /* DELTA_TOOL_INTERNAL_BSDIFF_BSDIFF_HELPER_H_ */
