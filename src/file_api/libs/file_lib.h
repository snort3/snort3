//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// file_lib.h author Hui Cao <huica@cisco.com>

#ifndef FILE_LIB_H
#define FILE_LIB_H

// This will be basis of file class
// FIXIT-L This will be refactored soon
#include <stdint.h>

#include "file_api/file_api.h"
#include "flow/flow.h"

#define SNORT_FILE_TYPE_UNKNOWN          UINT16_MAX  /**/
#define SNORT_FILE_TYPE_CONTINUE         0 /**/

struct FileCaptureInfo;
class FileConfig;

struct FileContext
{
    bool file_type_enabled;
    bool file_signature_enabled;
    uint8_t* file_name;
    uint32_t file_name_size;
    uint64_t file_size;
    bool upload;
    uint64_t processed_bytes;
    uint32_t file_type_id;
    uint8_t* sha256;
    void* file_type_context;
    void* file_signature_context;
    FileConfig* file_config;
    time_t expires;
    uint16_t   app_id;
    bool file_capture_enabled;
    FileCaptureInfo *file_capture;
    uint8_t *current_data;  /*current file data*/
    uint32_t current_data_len;
    File_Verdict verdict;
    bool suspend_block_verdict;
    FileState file_state;
    uint32_t file_id;
    uint32_t file_config_version;
};

/*Main File Processing functions */
void file_type_id(FileContext* context, uint8_t* file_data, int data_size, FilePosition position);
void file_signature_sha256(FileContext* context, uint8_t* file_data, int data_size, FilePosition
    position);

/*File context management*/
FileContext* file_context_create(void);
void file_context_reset(FileContext* context);
void file_context_free(void* context);
/*File properties*/
void file_name_set(FileContext* context, uint8_t* file_name, uint32_t name_size);
int file_name_get(FileContext* context, uint8_t** file_name, uint32_t* name_size);
void file_size_set(FileContext* context, uint64_t file_size);
uint64_t file_size_get(FileContext* context);
void file_direction_set(FileContext* context, bool upload);
bool file_direction_get(FileContext* context);
void file_sig_sha256_set(FileContext* context, uint8_t* signature);
uint8_t* file_sig_sha256_get(FileContext* context);

const char* file_type_name(void* conf, uint32_t id);

void free_file_identifiers(void*);
void file_sha256_print(unsigned char* hash);

#endif

