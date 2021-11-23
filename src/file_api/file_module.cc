//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
** Author(s):  Hui Cao <huica@cisco.com>
**
** NOTES
** 5.05.2012 - Initial Source Code. Hui Cao
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_module.h"

#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "trace/trace.h"

#include "file_service.h"
#include "file_stats.h"

using namespace snort;

THREAD_LOCAL const Trace* file_trace = nullptr;

static const Parameter file_magic_params[] =
{
    { "content", Parameter::PT_STRING, nullptr, nullptr,
      "file magic content" },

    { "offset", Parameter::PT_INT, "0:max32", "0",
      "file magic offset" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter file_rule_params[] =
{
    { "rev", Parameter::PT_INT, "0:max32", "0",
      "rule revision" },

    { "msg", Parameter::PT_STRING, nullptr, nullptr,
      "information about the file type" },

    { "type", Parameter::PT_STRING, nullptr, nullptr,
      "file type name" },

    { "id", Parameter::PT_INT, "0:max32", "0",
      "file type id" },

    { "category", Parameter::PT_STRING, nullptr, nullptr,
      "file type category" },

    { "group", Parameter::PT_STRING, nullptr, nullptr,
      "comma separated list of groups associated with file type" },

    { "version", Parameter::PT_STRING, nullptr, nullptr,
      "file type version" },

    { "magic", Parameter::PT_LIST, file_magic_params, nullptr,
      "list of file magic rules" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// File policy
static const Parameter file_when_params[] =
{
    // FIXIT-M when.policy_id should be an arbitrary string auto converted
    // into index for binder matching and lookups
    { "file_type_id", Parameter::PT_INT, "0:max32", "0",
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
    { "type_depth", Parameter::PT_INT, "0:max53", "1460",
      "stop type ID at this point" },

    { "signature_depth", Parameter::PT_INT, "0:max53", "10485760",
      "stop signature at this point" },

    { "block_timeout", Parameter::PT_INT, "0:max31", "86400",
      "stop blocking after this many seconds" },

    { "lookup_timeout", Parameter::PT_INT, "0:max31", "2",
      "give up on lookup after this many seconds" },

    { "block_timeout_lookup", Parameter::PT_BOOL, nullptr, "false",
      "block if lookup times out" },

    { "capture_memcap", Parameter::PT_INT, "0:max53", "100",
      "memcap for file capture in megabytes" },

    { "capture_max_size", Parameter::PT_INT, "0:max53", "1048576",
      "stop file capture beyond this point" },

    { "capture_min_size", Parameter::PT_INT, "0:max53", "0",
      "stop file capture if file size less than this" },

    { "capture_block_size", Parameter::PT_INT, "8:max53", "32768",
      "file capture block size in bytes" },

    { "max_files_cached", Parameter::PT_INT, "8:max53", "65536",
      "maximal number of files cached in memory" },

    { "max_files_per_flow", Parameter::PT_INT, "1:max53", "128",
      "maximal number of files able to be concurrently processed per flow" },

    { "enable_type", Parameter::PT_BOOL, nullptr, "true",
      "enable type ID" },

    { "enable_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable signature calculation" },

    { "enable_capture", Parameter::PT_BOOL, nullptr, "false",
      "enable file capture" },

    { "show_data_depth", Parameter::PT_INT, "0:max53", "100",
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

    { "verdict_delay", Parameter::PT_INT, "0:max53", "0",
      "number of queries to return final verdict" },

    { "b64_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "base64 decoding depth (-1 no limit)" },

    { "bitenc_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Non-Encoded MIME attachment extraction depth (-1 no limit)" },

    { "decompress_pdf", Parameter::PT_BOOL, nullptr, "false",
      "decompress pdf files" },

    { "decompress_swf", Parameter::PT_BOOL, nullptr, "false",
      "decompress swf files" },

    { "decompress_zip", Parameter::PT_BOOL, nullptr, "false",
      "decompress zip files" },

    { "decompress_buffer_size", Parameter::PT_INT, "1024:max31", "100000",
      "file decompression buffer size" },

    { "qp_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Quoted Printable decoding depth (-1 no limit)" },

    { "uu_decode_depth", Parameter::PT_INT, "-1:65535", "-1",
      "Unix-to-Unix decoding depth (-1 no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo file_pegs[] =
{
    { CountType::SUM, "total_files", "number of files processed" },
    { CountType::SUM, "total_file_data", "number of file data bytes processed" },
    { CountType::SUM, "cache_failures", "number of file cache add failures" },
    { CountType::SUM, "files_not_processed", "number of files not processed due to per-flow limit" },
    { CountType::MAX, "max_concurrent_files", "maximum files processed concurrently on a flow" },
    { CountType::END, nullptr, nullptr }
};

FileIdModule::FileIdModule() : Module(FILE_ID_NAME, FILE_ID_HELP, file_id_params) { }

FileIdModule::~FileIdModule()
{
    if (fc)
        delete fc;
}

void FileIdModule::set_trace(const Trace* trace) const
{ file_trace = trace; }

const TraceOption* FileIdModule::get_trace_options() const
{
    static const TraceOption filetrace_options(nullptr, 0, nullptr);
    return &filetrace_options;
}

const PegInfo* FileIdModule::get_pegs() const
{ return file_pegs; }

PegCount* FileIdModule::get_counts() const
{ return (PegCount*)&file_counts; }

static const RuleMap file_id_rules[] =
{
    { EVENT_FILE_DROPPED_OVER_LIMIT, "file not processed due to per flow limit" },
    { 0, nullptr }
};

const RuleMap* FileIdModule::get_rules() const
{
    return file_id_rules;
}

void FileIdModule::sum_stats(bool accumulate_now_stats)
{
    file_stats_sum();
    Module::sum_stats(accumulate_now_stats);
}

bool FileIdModule::set(const char*, Value& v, SnortConfig*)
{
    if (!fc)
        fc = new FileConfig;

    FilePolicy& fp = fc->get_file_policy();

    if ( v.is("type_depth") )
        fc->file_type_depth = v.get_int64();

    else if ( v.is("signature_depth") )
        fc->file_signature_depth = v.get_int64();

    else if ( v.is("block_timeout") )
        fc->file_block_timeout = v.get_int64();

    else if ( v.is("lookup_timeout") )
        fc->file_lookup_timeout = v.get_int64();

    else if ( v.is("block_timeout_lookup") )
        fc->block_timeout_lookup = v.get_bool();

    else if ( v.is("capture_memcap") )
        fc->capture_memcap = v.get_int64();

    else if ( v.is("capture_max_size") )
        fc->capture_max_size = v.get_int64();

    else if ( v.is("capture_min_size") )
        fc->capture_min_size = v.get_int64();

    else if ( v.is("capture_block_size") )
        fc->capture_block_size = v.get_int64();

    else if ( v.is("max_files_cached") )
        fc->max_files_cached = v.get_int64();

    else if ( v.is("max_files_per_flow") )
        fc->max_files_per_flow = v.get_uint64();

    else if ( v.is("enable_type") )
    {
        fp.set_file_type(v.get_bool());
    }
    else if ( v.is("enable_signature") )
    {
        fp.set_file_signature(v.get_bool());
    }
    else if ( v.is("enable_capture") )
    {
        if (v.get_bool() and Snort::is_reloading() and !FileService::is_file_capture_enabled())
        {
            ReloadError("Changing file_id.enable_capture requires a restart.\n");
            return false;
        }
        fp.set_file_capture(v.get_bool());
    }
    else if ( v.is("show_data_depth") )
        fc->show_data_depth = v.get_int64();

    else if ( v.is("trace_type") )
        fc->trace_type = v.get_bool();

    else if ( v.is("trace_signature") )
        fc->trace_signature = v.get_bool();

    else if ( v.is("trace_stream") )
        fc->trace_stream = v.get_bool();

    else if ( v.is("verdict_delay") )
    {
        fc->verdict_delay = v.get_int64();
        fp.set_verdict_delay(fc->verdict_delay);
    }
    else if ( v.is("decompress_pdf") )
        FileService::decode_conf.set_decompress_pdf(v.get_bool());

    else if ( v.is("decompress_swf") )
        FileService::decode_conf.set_decompress_swf(v.get_bool());

    else if ( v.is("decompress_zip") )
        FileService::decode_conf.set_decompress_zip(v.get_bool());

    else if ( v.is("decompress_buffer_size") )
        FileService::decode_conf.set_decompress_buffer_size(v.get_uint32());

    else if (v.is("b64_decode_depth"))
    {
        int32_t value = v.get_int32();
        int32_t mime = value > 0 ? value : -(value+1);
        FileService::decode_conf.set_b64_depth(mime);
    }
    else if (v.is("bitenc_decode_depth"))
    {
        int32_t value = v.get_int32();
        int32_t mime = value > 0 ? value : -(value+1);
        FileService::decode_conf.set_bitenc_depth(mime);
    }
    else if (v.is("qp_decode_depth"))
    {
        int32_t value = v.get_int32();
        int32_t mime = value > 0 ? value : -(value+1);
        FileService::decode_conf.set_qp_depth(mime);
    }
    else if (v.is("uu_decode_depth"))
    {
        int32_t value = v.get_int32();
        int32_t mime = value > 0 ? value : -(value+1);
        FileService::decode_conf.set_uu_depth(mime);
    }

    else if ( v.is("file_rules") )
        return true;

    else if ( v.is("rev") )
        rule.rev = v.get_uint32();

    else if ( v.is("msg") )
        rule.message = v.get_string();

    else if ( v.is("type") )
        rule.type = v.get_string();

    else if ( v.is("id") )
        rule.id = v.get_uint32();

    else if ( v.is("category") )
        rule.category = v.get_string();

    else if ( v.is("group") )
    {
        std::istringstream stream(v.get_string());
        std::string tmpstr;
        while (std::getline(stream, tmpstr, ','))
        {
            rule.groups.emplace_back(tmpstr);
        }
    }

    else if ( v.is("version") )
        rule.version = v.get_string();

    else if ( v.is("magic") )
        return true;

    else if ( v.is("content") )
        magic.content_str = v.get_string();

    else if ( v.is("offset") )
        magic.offset = v.get_uint32();

    else if ( v.is("file_policy") )
        return true;

    else if ( v.is("when") )
        return true;

    else if ( v.is("file_type_id") )
        file_rule.when.type_id = v.get_uint32();

    else if ( v.is("sha256") )
        file_rule.when.sha256 = v.get_string();

    else if ( v.is("use") )
        return true;

    else if ( v.is("verdict") )
    {
        file_rule.use.verdict = (FileVerdict)v.get_uint8();
        if (file_rule.use.verdict == FileVerdict::FILE_VERDICT_REJECT)
            need_active = true;
    }

    else if ( v.is("enable_file_type") )
        file_rule.use.type_enabled = v.get_bool();

    else if ( v.is("enable_file_signature") )
        file_rule.use.signature_enabled = v.get_bool();

    else if ( v.is("enable_file_capture") )
    {
        file_rule.use.capture_enabled = v.get_bool();
        if (file_rule.use.capture_enabled && Snort::is_reloading()
            && !FileService::is_file_capture_enabled())
        {
            ReloadError("Changing file_id.enable_file_capture requires a restart.\n");
            return false;
        }
    }
    return true;
}

bool FileIdModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if (!idx)
        return true;

    if ( !strcmp(fqn, "file_id.file_rules") )
    {
        rule.clear();
    }
    else if ( !strcmp(fqn, "file_id.file_rules.magic") )
    {
        magic.clear();
    }
    else if ( !strcmp(fqn, "file_id.file_policy") )
    {
        file_rule.clear();
    }

    return true;
}

bool FileIdModule::end(const char* fqn, int idx, SnortConfig*)
{
    if (!idx)
        return true;

    if ( !strcmp(fqn, "file_id.file_rules") )
    {
        fc->process_file_rule(rule);
    }
    else if ( !strcmp(fqn, "file_id.file_rules.magic") )
    {
        fc->process_file_magic(magic);
        rule.file_magics.emplace_back(magic);
    }
    else if ( !strcmp(fqn, "file_id.file_policy") )
    {
        fc->process_file_policy_rule(file_rule);
    }

    return true;
}

void FileIdModule::load_config(FileConfig*& dst)
{
    dst = fc;

    if (fc)
    {
        fc->get_file_policy().load();
        fc = nullptr;
    }
}

void FileIdModule::show_dynamic_stats()
{
    file_stats_print();
}

void FileIdModule::reset_stats()
{
    file_stats_clear();
    Module::reset_stats();
}
