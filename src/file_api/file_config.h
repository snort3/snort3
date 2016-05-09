//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "file_lib.h"
#include "file_identifier.h"
#include "file_api/file_policy.h"
#include "framework/module.h"

#define DEFAULT_FILE_TYPE_DEPTH 1460
#define DEFAULT_FILE_SIGNATURE_DEPTH 10485760 /*10 Mbytes*/
#define DEFAULT_FILE_SHOW_DATA_DEPTH 100
#define DEFAULT_FILE_BLOCK_TIMEOUT 86400 /*1 day*/
#define DEFAULT_FILE_LOOKUP_TIMEOUT 2    /*2 seconds*/
#define DEFAULT_FILE_CAPTURE_MEM            100         // 100 MiB
#define DEFAULT_FILE_CAPTURE_MAX_SIZE       1048576     // 1 MiB
#define DEFAULT_FILE_CAPTURE_MIN_SIZE       0           // 0
#define DEFAULT_FILE_CAPTURE_BLOCK_SIZE     32768       // 32 KiB
class FileConfig
{
public:
    FileMagicRule* get_rule_from_id(uint32_t);
    void process_file_rule(FileMagicRule&);
    void process_file_policy_rule(FileRule&);
    bool process_file_magic(FileMagicData&);
    uint32_t find_file_type_id(const uint8_t* buf, int len, uint64_t file_offset, void** context);
    FilePolicy& get_file_policy() {return filePolicy;}
    std::string file_type_name( uint32_t id);

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

    static int64_t show_data_depth;
    static bool trace_type;
    static bool trace_signature;
    static bool trace_stream;

private:
    FileIdentifier fileIdentifier;
    FilePolicy filePolicy;
};


//-------------------------------------------------------------------------
// file_id module
//-------------------------------------------------------------------------

static const Parameter file_magic_params[] =
{
    { "content", Parameter::PT_STRING, nullptr, nullptr,
      "file magic content" },

    { "offset", Parameter::PT_INT, "0:", "0",
      "file magic offset" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_rule_params[] =
{
    { "rev", Parameter::PT_INT, "0:", "0",
      "rule revision" },

    { "msg", Parameter::PT_STRING, nullptr, nullptr,
      "information about the file type" },

    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "file type name" },

    { "id", Parameter::PT_INT, "0:", "0",
      "file type id" },

    { "category", Parameter::PT_STRING, nullptr, nullptr,
      "file type category" },

    { "version", Parameter::PT_STRING, nullptr, nullptr,
      "file type version" },

    { "magic", Parameter::PT_LIST, file_magic_params, nullptr,
      "list of file magic rules" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// File policy
static const Parameter file_when_params[] =
{
    // FIXIT when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups
    { "file_type_id", Parameter::PT_INT, "0:", "0",
      "unique ID for file type in file magic rule" },

    { "sha256", Parameter::PT_STRING, nullptr, nullptr,
      "SHA 256" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_use_params[] =
{
    { "verdict", Parameter::PT_ENUM, "unknown | log | stop | block | reset ", "unknown",
      "what to do with matching traffic" },

    { "enable_file_type", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file type identification" },

    { "enable_file_signature", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file signature" },

    { "enable_file_capture", Parameter::PT_BOOL, nullptr, "false",
      "true/false -> enable/disable file capture" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_policy_rule_params[] =
{
    { "when", Parameter::PT_TABLE, file_when_params, nullptr,
      "match criteria" },

    { "use", Parameter::PT_TABLE, file_use_params, nullptr,
      "target configuration" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_id_params[] =
{
    { "type_depth", Parameter::PT_INT, "0:", "1460",
      "stop type ID at this point" },

    { "signature_depth", Parameter::PT_INT, "0:", "10485760",
      "stop signature at this point" },

    { "block_timeout", Parameter::PT_INT, "0:", "86400",
      "stop blocking after this many seconds" },

    { "lookup_timeout", Parameter::PT_INT, "0:", "2",
      "give up on lookup after this many seconds" },

    { "block_timeout_lookup", Parameter::PT_BOOL, nullptr, "false",
      "block if lookup times out" },

    { "capture_memcap", Parameter::PT_INT, "0:", "100",
      "memcap for file capture in megabytes" },

    { "capture_max_size", Parameter::PT_INT, "0:", "1048576",
      "stop file capture beyond this point" },

    { "capture_min_size", Parameter::PT_INT, "0:", "0",
      "stop file capture if file size less than this" },

    { "capture_block_size", Parameter::PT_INT, "8:", "32768",
      "file capture block size in bytes" },

    { "enable_type", Parameter::PT_BOOL, nullptr, "false",
      "enable type ID" },

    { "enable_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable signature calculation" },

    { "enable_capture", Parameter::PT_BOOL, nullptr, "false",
      "enable file capture" },

    { "show_data_depth", Parameter::PT_INT, "0:", "100",
      "print this many octets" },

    { "file_rules", Parameter::PT_LIST, file_rule_params, nullptr,
      "list of file magic rules" },

    { "file_policy", Parameter::PT_LIST, file_policy_rule_params, nullptr,
      "list of file rules" },

    { "trace_type", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of type info" },

    { "trace_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of signature info" },

    { "trace_stream", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of file data" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


#define file_id_help \
    "configure file identification"

class FileIdModule : public Module
{
public:
    FileIdModule() : Module("file_id", file_id_help, file_id_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

private:
    FileMagicRule rule;
    FileMagicData magic;
    FileRule file_rule;
};

#endif

