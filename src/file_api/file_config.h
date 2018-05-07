//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// file_config.h author Hui Cao <huica@cisco.com>

#ifndef FILE_CONFIG_H
#define FILE_CONFIG_H

// This provides the basic configuration for file processing

#include "file_api/file_identifier.h"
#include "file_api/file_policy.h"

#define DEFAULT_FILE_TYPE_DEPTH 1460
#define DEFAULT_FILE_SIGNATURE_DEPTH 10485760 /*10 Mbytes*/
#define DEFAULT_FILE_SHOW_DATA_DEPTH 100
#define DEFAULT_FILE_BLOCK_TIMEOUT 86400 /*1 day*/
#define DEFAULT_FILE_LOOKUP_TIMEOUT 2    /*2 seconds*/
#define DEFAULT_FILE_CAPTURE_MEM            100         // 100 MiB
#define DEFAULT_FILE_CAPTURE_MAX_SIZE       1048576     // 1 MiB
#define DEFAULT_FILE_CAPTURE_MIN_SIZE       0           // 0
#define DEFAULT_FILE_CAPTURE_BLOCK_SIZE     32768       // 32 KiB
#define DEFAULT_MAX_FILES_CACHED            65536

#define FILE_ID_NAME "file_id"
#define FILE_ID_HELP "configure file identification"

class FileConfig
{
public:
    FileMagicRule* get_rule_from_id(uint32_t);
    void get_magic_rule_ids_from_type(const std::string&, const std::string&,
        snort::FileTypeBitSet&);
    void process_file_rule(FileMagicRule&);
    void process_file_policy_rule(FileRule&);
    bool process_file_magic(FileMagicData&);
    uint32_t find_file_type_id(const uint8_t* buf, int len, uint64_t file_offset, void** context);
    FilePolicy& get_file_policy() { return filePolicy; }
    std::string file_type_name(uint32_t id);

    int64_t file_type_depth = DEFAULT_FILE_TYPE_DEPTH;
    int64_t file_signature_depth = DEFAULT_FILE_SIGNATURE_DEPTH;
    int64_t file_block_timeout = DEFAULT_FILE_BLOCK_TIMEOUT;
    int64_t file_lookup_timeout = DEFAULT_FILE_LOOKUP_TIMEOUT;
    bool block_timeout_lookup = false;
    int64_t capture_memcap = DEFAULT_FILE_CAPTURE_MEM;
    int64_t capture_max_size = DEFAULT_FILE_CAPTURE_MAX_SIZE;
    int64_t capture_min_size = DEFAULT_FILE_CAPTURE_MIN_SIZE;
    int64_t capture_block_size = DEFAULT_FILE_CAPTURE_BLOCK_SIZE;
    int64_t file_depth =  0;
    int64_t max_files_cached = DEFAULT_MAX_FILES_CACHED;

    int64_t show_data_depth = DEFAULT_FILE_SHOW_DATA_DEPTH;
    bool trace_type = false;
    bool trace_signature = false;
    bool trace_stream = false;
    int64_t verdict_delay = 0;

private:
    FileIdentifier fileIdentifier;
    FilePolicy filePolicy;
};

std::string file_type_name(uint32_t id);
FileConfig* get_file_config();
#endif

