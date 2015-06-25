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
/*
**  Author(s):  Hui Cao <huica@cisco.com>
**
**  NOTES
**  5.25.12 - Initial Source Code. Hui Cao
*/

#ifndef FILE_LIB_H
#define FILE_LIB_H

#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "file_api/file_api.h"
#include "flow/flow.h"

#define SNORT_FILE_TYPE_UNKNOWN          UINT16_MAX  /**/
#define SNORT_FILE_TYPE_CONTINUE         0 /**/

struct FileCaptureInfo;
class FileConfig;


class FileContext
{
public:
     FileContext():
        file_type_enabled(false),
        file_signature_enabled(false),
        file_capture_enabled(false),
        file_name(NULL),
        file_name_size(0),
        file_size(0),
        direction(FILE_DOWNLOAD),
        processed_bytes(0),
        file_type_id(0),
        sha256(NULL),
        file_type_context(NULL),
        file_signature_context(NULL),
        file_config(NULL),
        expires(0),
        file_capture(NULL),
        current_data(NULL), /*current file data*/
        current_data_len(0),
        verdict(FILE_VERDICT_UNKNOWN),
        suspend_block_verdict(false),
        file_state({FILE_CAPTURE_SUCCESS, FILE_SIG_PROCESSING}),
        file_id(0),
        file_config_version(0){}
     ~FileContext();

    /* main processing functions */
    void file_type_eval(const uint8_t* file_data, int data_size, FilePosition position);
    void file_signature_sha256_eval(const uint8_t* file_data, int data_size, FilePosition pos);
    void updateFileSize(int data_size, FilePosition position);

    uint32_t get_file_type();
    void config_file_type(bool enabled);
    bool is_file_type_enabled();
    void config_file_signature(bool enabled);
    bool is_file_signature_enabled();
    void config_file_capture(bool enabled);
    bool is_file_capture_enabled();

    /*File properties*/
    void set_file_name(const uint8_t* file_name, uint32_t name_size);
    bool get_file_name( uint8_t** file_name, uint32_t* name_size);
    void set_file_size(uint64_t size);
    uint64_t get_file_size();
    void set_file_direction(FileDirection dir);
    FileDirection get_file_direction();
    void set_file_sig_sha256(uint8_t* signature);
    uint8_t* get_file_sig_sha256();
    void set_file_id(uint32_t size);
    uint32_t get_file_id();

    void print_file_sha256();

private:
    bool file_type_enabled;
    bool file_signature_enabled;
    bool file_capture_enabled;
    uint8_t* file_name;
    uint32_t file_name_size;
    uint64_t file_size;
    FileDirection direction;
    uint64_t processed_bytes;
    uint32_t file_type_id;
    uint8_t* sha256;
    void* file_type_context;
    void* file_signature_context;
    FileConfig* file_config;
    time_t expires;
    FileCaptureInfo *file_capture;
    uint8_t *current_data;  /*current file data*/
    uint32_t current_data_len;
    File_Verdict verdict;
    bool suspend_block_verdict;
    FileState file_state;
    uint32_t file_id;
    uint32_t file_config_version;

    inline int get_data_size_from_depth_limit(FileProcessType type, int data_size);
    inline void finalize_file_type ();

};

const char* file_type_name(void* conf, uint32_t id);

void free_file_identifiers(void*);

#endif

