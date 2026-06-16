//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/module_manager.h"
#include "packet_io/active.h"
#include "trace/trace.h"

#include "file_service.h"
#include "file_stats.h"

#include "parser/parser.h"

using namespace snort;

THREAD_LOCAL const Trace* file_trace = nullptr;
extern THREAD_LOCAL snort::ProfileStats file_perf_stats;

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

    { "show_data_depth", Parameter::PT_INT, "0:max53", "100",
      "print this many octets" },

    { "rules_file", Parameter::PT_STRING, nullptr, nullptr,
      "name of file with IPS rules for file identification" },

    { "trace_type", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of type info" },

    { "trace_signature", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of signature info" },

    { "trace_stream", Parameter::PT_BOOL, nullptr, "false",
      "enable runtime dump of file data" },

    { "decompress_buffer_size", Parameter::PT_INT, "1024:max31", "100000",
      "file decompression buffer size" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo file_pegs[] =
{
    { CountType::SUM, "total_files", "number of files processed" },
    { CountType::SUM, "total_file_data", "number of file data bytes processed" },
    { CountType::SUM, "cache_failures", "number of file cache add failures" },
    { CountType::SUM, "files_not_processed", "number of files not processed due to per-flow limit" },
    { CountType::MAX, "max_concurrent_files", "maximum files processed concurrently on a flow" },
    { CountType::MAX, "buffers_max", "maximum number of file buffers that can be allocated" },
    { CountType::NOW, "buffers_in_use", "number of file buffers currently in use" },
    { CountType::SUM, "files_buffered_total", "number of files that entered multi-packet buffering" },
    { CountType::SUM, "files_released_total", "reserved files released back to pool (cross-thread)" },
    { CountType::SUM, "files_freed_total", "unreserved files freed back to pool (same-thread)" },
    { CountType::SUM, "files_captured_total", "files successfully reserved for external use" },
    { CountType::SUM, "file_memcap_failures_total", "alloc failed - file mempool exhausted" },
    { CountType::SUM, "file_reserve_failures", "any file reserve failure" },
    { CountType::SUM, "size_below_min", "files rejected below minimum capture size" },
    { CountType::SUM, "size_above_limit", "files rejected above the capture size limit" },
    { CountType::SUM, "single_packet_files", "files fitting in a single packet" },
    { CountType::MAX, "buffers_used_max", "peak simultaneous buffer usage" },
    { CountType::SUM, "buffers_allocated", "total blocks allocated from file mempool" },
    { CountType::SUM, "buffers_freed_total", "total blocks freed to pool (same-thread)" },
    { CountType::SUM, "buffers_released_total", "total blocks released to pool (cross-thread)" },
    { CountType::SUM, "buffers_free_errors", "block free operation failures" },
    { CountType::SUM, "buffers_release_errors", "block release operation failures" },
    { CountType::SUM, "sig_depth_exceeded", "files bypassing inspection due to signature depth limit" },
    { CountType::SUM, "file_lookup_timeouts", "files where DM never responded within timeout" },
    { CountType::SUM, "file_cache_hits", "file cache lookups that found a known verdict" },
    { CountType::SUM, "file_cache_misses", "file cache lookups that did not find a verdict" },
    { CountType::SUM, "file_cache_total_entries", "total files ever inserted into the file cache" },
    { CountType::SUM, "file_cache_full", "file cache at the configured entry limit - no room for new entry" },
    { CountType::SUM, "file_cache_failures", "file cache add failed for reasons other than being full (e.g., duplicate key)" },
    { CountType::MAX, "file_cache_max_entries", "peak number of entries ever in the file cache" },
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

ProfileStats* FileIdModule::get_profile() const
{ return &file_perf_stats; }

const PegInfo* FileIdModule::get_pegs() const
{ return file_pegs; }

PegCount* FileIdModule::get_counts() const
{
    file_counts_update_buffers();
    return (PegCount*)&file_counts;
}

static const RuleMap file_id_rules[] =
{
    { EVENT_FILE_DROPPED_OVER_LIMIT, "file not processed due to per flow limit" },
    { 0, nullptr }
};

const RuleMap* FileIdModule::get_rules() const
{
    return file_id_rules;
}

void FileIdModule::sum_stats(bool dump_stats)
{
    if ( dump_stats )
        file_stats_sum();
    Module::sum_stats(dump_stats);
    file_counts_update_buffers();
}

bool FileIdModule::set(const char*, Value& v, SnortConfig*)
{
    if (!fc)
        fc = new FileConfig;

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

    else if ( v.is("show_data_depth") )
        fc->show_data_depth = v.get_int64();

    else if ( v.is("trace_type") )
        fc->trace_type = v.get_bool();

    else if ( v.is("trace_signature") )
        fc->trace_signature = v.get_bool();

    else if ( v.is("trace_stream") )
        fc->trace_stream = v.get_bool();

    else if ( v.is("decompress_buffer_size") )
        FileService::decode_conf.set_decompress_buffer_size(v.get_uint32());

    else if ( v.is("rules_file") )
    {
        magic_file = "include ";
        magic_file += v.get_string();
    }

    return true;
}

bool FileIdModule::end(const char*, int, SnortConfig*)
{
    const char* inc = ModuleManager::get_includer(get_name());
    parser_append_rules_special(magic_file.c_str(), inc);
    return true;
}

void FileIdModule::load_config(FileConfig*& dst)
{
    dst = fc;
    fc = nullptr;
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
