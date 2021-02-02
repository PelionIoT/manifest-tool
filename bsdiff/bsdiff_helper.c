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
#include "common.h"
#include "bsdiff.h"
#include "bsdiff_helper.h"
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

//#ifdef __unix
//#if defined(__gnuc__)
#if !defined(__CYGWIN__) && !defined(_WIN32)
#define fopen_s(pFile, filename, mode) ((*(pFile)) = fopen((filename), (mode))) == NULL
#endif

#define ERR(msg) do { \
    deliver_error(msg); \
    status = -1; \
    goto end; \
    } while(0)

void offtout(int64_t x, uint8_t *buf);

static int file_write(struct bsdiff_stream* stream, const void* buffer,
        uint64_t size) {
    return fwrite(buffer, sizeof(uint8_t), size, (FILE*) stream->opaque) == size ? 0 : -1;
}


int do_diff(
        const char* old_fw_img,
        const char* new_fw_img,
        const char* delta_file,
        int64_t max_frame_size
)
{
    int status = 0;
    uint8_t *old_data = NULL;
    uint8_t *new_data = NULL;
    size_t old_size = 0;
    size_t new_size = 0;
    uint8_t buf[24] = {0};
    FILE *delta_fp = NULL;
    FILE *old_fp = NULL;
    FILE *new_fp = NULL;

    int64_t max_deCompressBuffer_size = 0;
    int64_t patch_file_size = 0;

    /* --------------- Load old FW -------------------------------------------*/
    {
        if (fopen_s(&old_fp, old_fw_img, "rb")){
            ERR("Failed to open old FW image");
        }

        fseek(old_fp, 0L, SEEK_END);
        old_size = ftell(old_fp);
        if (0 >= old_size) {
            ERR("Malformed old FW image");
        }
        fseek(old_fp, 0L, SEEK_SET);

        /* Allocate oldsize+1 bytes instead of oldsize bytes to ensure
             that we never try to malloc(0) and get a NULL pointer */
        old_data = malloc(old_size + 1);
        if (NULL == old_data){
            ERR("Failed to allocate memory for old FW image");
        }

        if (1 != fread(old_data, old_size, 1, old_fp)) {
            ERR("Failed to read old FW image");
        }

    }
    /* -------------- Load new FW --------------------------------------------*/
    {
        if (fopen_s(&new_fp, new_fw_img, "rb")){
            ERR("Failed to open new FW image");
        }

        fseek(new_fp, 0L, SEEK_END);
        new_size = ftell(new_fp);
        if (0 >= new_size) {
            ERR("Malformed new FW image");
        }
        fseek(new_fp, 0L, SEEK_SET);

        /* Allocate newsize+1 bytes instead of newsize bytes to ensure
             that we never try to malloc(0) and get a NULL pointer */
        new_data = malloc(new_size + 1);
        if (NULL == new_data){
            ERR("Failed to allocate memory for new FW image");
        }

        if (1 != fread(new_data, new_size, 1, new_fp)) {
            ERR("Failed to read new FW image");
        }

    }

    /* ------------------- Create the patch file -----------------------------*/
    if (fopen_s(&delta_fp, delta_file, "wb")) {
        ERR("Failed to create delta file");
    }

    /* Write header (signature+newsize+max undeCompressBuffer+maxdeCompressBuffer)*/
    offtout(new_size, buf);
    offtout(max_frame_size, buf + 8);
    offtout(max_deCompressBuffer_size, buf + 16);
    if (
            (1 != fwrite(FILE_MAGIC, FILE_MAGIC_LEN, 1, delta_fp)) ||
            (1 != fwrite(buf, sizeof(buf), 1, delta_fp))
    ) {
        ERR("Failed to write header");
    }

    struct bsdiff_stream stream = {
        .malloc = malloc,
        .free = free,
        .write = file_write,
        .opaque = delta_fp

    };
    if (bsdiff(old_data, old_size, new_data, new_size, &stream, &max_deCompressBuffer_size,
                    max_frame_size)) {
        ERR("bsdiff failed");
    }

    /* Go back to header and fill the maxdeCompressBuffer properly */
    offtout(max_deCompressBuffer_size, buf);
    fseek(delta_fp, 32, SEEK_SET);
    if (fwrite(buf, 1, 8, delta_fp) != 8) {
        ERR("Failed to write maxdeCompressBuffer");
    }

    fseek(delta_fp, 0, SEEK_END);
    patch_file_size = ftell(delta_fp);

end:
    if (0 == status){
        printf(
            "Wrote diff file %s, size %lld. Max undeCompressBuffer frame size was %lld, max deCompressBuffer frame size was %lld.\n",
            delta_file, patch_file_size, max_frame_size,
            max_deCompressBuffer_size
        );
    }

    if (old_fp){
        fclose(old_fp);
    }

    if (new_fp){
        fclose(new_fp);
    }

    if (delta_fp){
        fclose(delta_fp);
    }

    if(old_data){
        free(old_data);
    }
    if (new_data){
        free(new_data);
    }

    return status;
}

const char *bsdiff_get_version(void)
{
    return FILE_MAGIC;
}
