//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
 ** 8.15.15 - Initial Source Code. Hui Cao
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_flows.h"

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "packet_tracer/packet_tracer.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"

#include "file_cache.h"
#include "file_config.h"
#include "file_lib.h"
#include "file_module.h"
#include "file_service.h"
#include "file_stats.h"
#include <thread>

using namespace snort;

unsigned FileFlows::file_flow_data_id = 0;
static THREAD_LOCAL uint32_t max_file_id = 0;

namespace snort
{
    FilePosition get_file_position(Packet* pkt)
    {
        FilePosition position = SNORT_FILE_POSITION_UNKNOWN;
        Packet* p = (Packet*)pkt;

        if (p->is_full_pdu())
            position = SNORT_FILE_FULL;
        else if (p->is_pdu_start())
            position = SNORT_FILE_START;
        else if (p->packet_flags & PKT_PDU_TAIL)
            position = SNORT_FILE_END;
        else if (get_file_processed_size(p->flow))
            position = SNORT_FILE_MIDDLE;

        return position;
    }
}

static void populate_trace_data(FileContext* context)
{
    std::stringstream ss;
    context->print_file_name(ss);
    std::string file_name = ss.str();

    PacketTracer::daq_log("file+%" PRId64"+Matched policy id %u, identification %s, signature %s, capture %s+"
                "File with ID %lu, name %s, type %s, size %lu, SHA %s detected. Verdict %s.$",
                TO_NSECS(pt_timer->get()),
                context->get_policy_id(),
                ((context->is_file_type_enabled() || context->get_file_type() || context->get_file_sig_sha256()) ? "<on>" : "<off>"),
                ((context->is_file_signature_enabled() || context->get_file_sig_sha256()) ? "<on>" : "<off>"),
                (context->is_file_capture_enabled() ? "<on>" : "<off>"),
                context->get_file_id(),
                (file_name.empty() ? "<empty>" : file_name.c_str()),
                file_type_name(context->get_file_type()).c_str(),
                context->get_file_size(),
                (context->get_file_sig_sha256() ? context->sha_to_string(context->get_file_sig_sha256()).c_str(): "<empty>"),
                VerdictName[context->verdict].c_str());
}

void FileFlows::handle_retransmit(Packet* p)
{
    FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
        "handle_retransmit:queried for verdict\n");
    if (file_policy == nullptr)
        return;

    bool is_new_context = false;
    FileContext* file = get_file_context(pending_file_id, false, is_new_context);
    if ((file == nullptr) or (file->verdict != FILE_VERDICT_PENDING))
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
            "handle_retransmit:context is null or verdict not pending, returning\n");
        return;
    }

    FileContext* file_got = nullptr;
    FileCache* file_cache = FileService::get_file_cache();

    if (!file->get_file_data())
    {
        if (file_cache)
            file_got = file_cache->get_file(flow, pending_file_id, false);
        if (file_got and file_got->get_file_data() and file_got->verdict == FILE_VERDICT_PENDING)
        {
            file_got->user_file_data_mutex.lock();
            file->set_file_data(file_got->get_file_data());
            file_got->set_file_data(nullptr);
            file_got->user_file_data_mutex.unlock();
        }
    }
    file->user_file_data_mutex.lock();
    FileVerdict verdict = file_policy->signature_lookup(p, file);
    file->user_file_data_mutex.unlock();

    if (file_cache)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
            "handle_retransmit:applying file cache verdict %d\n", verdict);
        file_cache->apply_verdict(p, file, verdict, false, file_policy);
    }
    file->log_file_event(flow, file_policy);
}

FileFlows* FileFlows::get_file_flows(Flow* flow, bool to_create)
{
    FileFlows* fd = (FileFlows*)flow->get_flow_data(FileFlows::file_flow_data_id);

    if (!to_create or fd)
        return fd;

    FileInspect* fi = (FileInspect*)InspectorManager::get_file_inspector();

    if (FileService::is_file_service_enabled() and fi)
    {
        fd = new FileFlows(flow, fi);
        flow->set_flow_data(fd);
        fd->set_file_policy(get_network_policy()->get_base_file_policy());
    }

    return fd;
}

FilePolicyBase* FileFlows::get_file_policy(Flow* flow)
{
    FileFlows* fd = (FileFlows*)flow->get_flow_data(FileFlows::file_flow_data_id);

    if (fd)
        return fd->get_file_policy();

    return nullptr;
}

void FileFlows::set_current_file_context(FileContext* ctx)
{
    // If we finished processing a file context object last time, delete it
    if (current_context_delete_pending and (current_context != ctx))
    {
        int64_t file_id  = current_context->get_file_id();
        delete current_context;
        current_context_delete_pending = false;
        FileCache* file_cache = FileService::get_file_cache();
        assert(file_cache);
        FileContext* file_got = file_cache->get_file(flow, file_id, false);
        if (file_got and file_got->verdict == FILE_VERDICT_PENDING and current_context != file_got)
        {
            file_got->user_file_data_mutex.lock();
            delete(file_got->get_file_data());
            file_got->set_file_data(nullptr);
            file_got->user_file_data_mutex.unlock();
        }
    }
    current_context = ctx;
    // Not using current_file_id so clear it
    current_file_id = 0;
}

FileContext* FileFlows::get_current_file_context()
{
    if (current_file_id)
    {
        bool is_new_context = false;
        return get_file_context(current_file_id, false, is_new_context);
    }
    return current_context;
}

uint64_t FileFlows::get_new_file_instance()
{
    uint64_t thread_id = get_instance_id();
    return ((thread_id << 32) | max_file_id++);
}

FileFlows::~FileFlows()
{
    std::lock_guard<std::mutex> guard(file_flow_context_mutex);
    FileCache* file_cache = FileService::get_file_cache();
    assert(file_cache);
    uint64_t file_id = 0;
    if (current_context)
        file_id = current_context->get_file_id();
    else if (main_context)
        file_id = main_context->get_file_id();

    FileContext* file_got = file_cache->get_file(flow, file_id, false);

    if (file_got and (file_got->verdict == FILE_VERDICT_PENDING))
    {
        file_got->user_file_data_mutex.lock();
        delete (file_got->get_file_data());
        file_got->set_file_data(nullptr);
        file_got->user_file_data_mutex.unlock();
    }

    delete(main_context);
    if (current_context_delete_pending)
        delete(current_context);

    // Delete any remaining FileContexts stored on the flow
    for (auto const& elem : partially_processed_contexts)
    {
        delete elem.second;
    }

    FilePolicyBase::delete_file_policy(file_policy);
}

FileContext* FileFlows::find_main_file_context(FilePosition pos, FileDirection dir, size_t index)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context = main_context;

    if (context)
    {
        if ((pos == SNORT_FILE_MIDDLE)or (pos == SNORT_FILE_END))
            return context;
        else
            delete context;
    }

    context = new FileContext;
    main_context = context;
    context->check_policy(flow, dir, file_policy);

    if (!index)
    {
        context->set_file_id(get_new_file_instance());
        context->set_not_cacheable();
    }
    else
        context->set_file_id(index);

    return context;
}

FileContext* FileFlows::get_partially_processed_context(uint64_t file_id)
{
    auto elem = partially_processed_contexts.find(file_id);
    if (elem != partially_processed_contexts.end())
        return elem->second;
    return nullptr;
}

FileContext* FileFlows::get_file_context(
    uint64_t file_id, bool to_create, bool& is_new_context,
    uint64_t multi_file_processing_id)
{
    is_new_context = false;

    // First check if this file is currently being processed
    if (!multi_file_processing_id)
        multi_file_processing_id = file_id;
    FileContext* context = get_partially_processed_context(multi_file_processing_id);

    // Otherwise check if it has been fully processed and is in the file cache. If the file is not
    // in the cache, don't add it.
    if (!context)
    {
        FileCache* file_cache = FileService::get_file_cache();
        assert(file_cache);
        context = file_cache->get_file(flow, file_id, false);
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
            "get_file_context:trying to get context from cache\n");
    }

    // If we haven't found the context, create it and store it on the file flows object
    if (!context and to_create)
    {
        // If we have reached the max file per flow limit, alert and increment the peg count
        FileConfig* fc = get_file_config(SnortConfig::get_conf());
        if (partially_processed_contexts.size() == fc->max_files_per_flow)
        {
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, GET_CURRENT_PACKET,
               "max file per flow limit reached %lu\n", partially_processed_contexts.size());
            file_counts.files_over_flow_limit_not_processed++;
            events.create_event(EVENT_FILE_DROPPED_OVER_LIMIT);
        }
        else
        {
            context = new FileContext;
            is_new_context = true;
            partially_processed_contexts[multi_file_processing_id] = context;
            FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, GET_CURRENT_PACKET,
                "get_file_context:creating new context\n");
            if (partially_processed_contexts.size() > file_counts.max_concurrent_files_per_flow)
                file_counts.max_concurrent_files_per_flow = partially_processed_contexts.size();
        }
    }

    return context;
}

// Remove a file context from the flow's partially processed store. Don't delete the context
// yet because detection needs access; pointer is stored in current_context. The file context will
// be deleted when the next file is processed
void FileFlows::remove_processed_file_context(uint64_t file_id)
{
    FileContext *context = get_partially_processed_context(file_id);
    partially_processed_contexts.erase(file_id);
    if (context)
        current_context_delete_pending = true;
}

// Remove file context explicitly
void FileFlows::remove_processed_file_context(uint64_t file_id, uint64_t multi_file_processing_id)
{
    bool is_new_context = false;

    if (!multi_file_processing_id)
        multi_file_processing_id = file_id;

    FileContext* context = get_file_context(file_id, false, is_new_context, multi_file_processing_id);
    if (context)
    {
        set_current_file_context(context);
        context->processing_complete = true;
        remove_processed_file_context(multi_file_processing_id);
    }
}

/* This function is used to process file that is sent in pieces
 *
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileFlows::file_process(Packet* p, uint64_t file_id, const uint8_t* file_data,
    int data_size, uint64_t offset, FileDirection dir, uint64_t multi_file_processing_id,
    FilePosition position)
{
    int64_t file_depth = FileService::get_max_file_depth();
    bool continue_processing;
    bool cacheable = file_id or offset;
    bool is_new_context = false;

    if (!multi_file_processing_id)
        multi_file_processing_id = file_id;

    if ((file_depth < 0) or (offset > (uint64_t)file_depth))
    {
        FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
             "file depth less than zero or offset is more than file depth , returning\n");
        return false;
    }

    FileContext* context = get_file_context(file_id, true, is_new_context, multi_file_processing_id);

    if (!context)
    {
        FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_CRITICAL_LEVEL, p,
            "file_process:context missing, returning \n");
        return false;
    }

    if (PacketTracer::is_daq_activated())
        PacketTracer::pt_timer_start();

    if (!cacheable)
        context->set_not_cacheable();

    set_current_file_context(context);

    // Only increase file count when there are no queued segments
    // This will ensure we only count a file once in case it has
    // processed bytes 0 but many queued segments
    if (!context->get_processed_bytes() and !context->segments_queued())
    {
        context->check_policy(flow, dir, file_policy);
        context->set_file_id(file_id);
    }

    if (context->is_cacheable() and not is_new_context)
    {
        FileVerdict verdict = FileService::get_file_cache()->cached_verdict_lookup(p, context,
            file_policy);
        if (verdict != FILE_VERDICT_UNKNOWN and verdict != FILE_VERDICT_PENDING)
        {
            context->processing_complete = true;
            remove_processed_file_context(multi_file_processing_id);
            if (PacketTracer::is_daq_activated())
                populate_trace_data(context);
            return false;
        }
        else if (verdict == FILE_VERDICT_PENDING)
            return true;
    }

    if (context->processing_complete and context->verdict != FILE_VERDICT_UNKNOWN)
    {
        /*A new file session, but policy might be different*/
        context->check_policy(flow, dir, file_policy);

        if ((context->get_file_sig_sha256()) || !context->is_file_signature_enabled())
        {
            /* Just check file type and signature */
            FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
               "calling context processing for position full\n");
            continue_processing = context->process(p, file_data, data_size, SNORT_FILE_FULL,
                    file_policy);
            if (context->processing_complete)
                remove_processed_file_context(multi_file_processing_id);
            if (PacketTracer::is_daq_activated())
                populate_trace_data(context);
            return continue_processing;
        }
    }

    FILE_DEBUG(file_trace , DEFAULT_TRACE_OPTION_ID, TRACE_DEBUG_LEVEL, p,
       "calling context process data_size %d, offset %lu, position %d\n",
        data_size, offset, position);
    continue_processing = context->process(p, file_data, data_size, offset, file_policy, position);
    if (context->processing_complete)
        remove_processed_file_context(multi_file_processing_id);
    if (PacketTracer::is_daq_activated())
        populate_trace_data(context);
    return continue_processing;
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileFlows::file_process(Packet* p, const uint8_t* file_data, int data_size,
    FilePosition position, bool upload, size_t file_index)
{
    FileContext* context;
    FileDirection direction = upload ? FILE_UPLOAD : FILE_DOWNLOAD;
    /* if both disabled, return immediately*/
    if (!FileService::is_file_service_enabled())
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
           "file_process:file service not enabled, returning\n");
        return false;
    }

    if (position == SNORT_FILE_POSITION_UNKNOWN)
    {
        FILE_DEBUG(file_trace, DEFAULT_TRACE_OPTION_ID, TRACE_ERROR_LEVEL, p,
           "file_process:position of file is unknown, returning\n");
        return false;
    }

    if (PacketTracer::is_daq_activated())
        PacketTracer::pt_timer_start();

    context = find_main_file_context(position, direction, file_index);

    set_current_file_context(context);

    context->set_signature_state(gen_signature);
    bool file_process_ret = context->process(p, file_data, data_size, position, file_policy);
    if (PacketTracer::is_daq_activated())
        populate_trace_data(context);
    return file_process_ret;
}

/*
 * Return:
 *    true: continue processing this file
 *    false: ignore this file
 */
bool FileFlows::set_file_name(const uint8_t* fname, uint32_t name_size, uint64_t file_id,
    uint64_t multi_file_processing_id, const uint8_t* url, uint32_t url_size)
{
    bool is_new_context = false;
    FileContext* context;
    if (file_id)
        context = get_file_context(file_id, false, is_new_context, multi_file_processing_id);
    else
        context = get_current_file_context();
    if ( !context )
        return false;

    if ( !context->is_url_set() )
        context->set_url((const char*)url, url_size);

    if ( !context->is_file_name_set() )
    {
        context->set_file_name((const char*)fname, name_size);
        context->log_file_event(flow, file_policy);
    }

    if ((context->get_processed_bytes() == (uint64_t)FileService::get_max_file_depth()) or
        ((context->get_file_type() != SNORT_FILE_TYPE_CONTINUE) and
            (!context->is_file_capture_enabled()) and (!context->is_file_signature_enabled())))
    {
        context->processing_complete = true;
        // this can be called by inspector also if needed instead of here based on return value
        remove_processed_file_context(multi_file_processing_id);
        return false;
    }
    return true;
}

void FileFlows::add_pending_file(uint64_t file_id)
{
    current_file_id = pending_file_id = file_id;
}

FileInspect::FileInspect(FileIdModule* fm)
{
    fm->load_config(config);
}

FileInspect:: ~FileInspect()
{
    if (config)
        delete config;
}

bool FileInspect::configure(SnortConfig*)
{
    if (!config)
        return true;

    FileCache* file_cache = FileService::get_file_cache();
    if (file_cache)
    {
        file_cache->set_block_timeout(config->file_block_timeout);
        file_cache->set_lookup_timeout(config->file_lookup_timeout);
        file_cache->set_max_files(config->max_files_cached);
    }

    return true;
}

static void file_config_show(const FileConfig* fc)
{
    if ( ConfigLogger::log_flag("enable_type", FileService::is_file_type_id_enabled()) )
        ConfigLogger::log_value("type_depth", fc->file_type_depth);

    if ( ConfigLogger::log_flag("enable_signature", FileService::is_file_signature_enabled()) )
        ConfigLogger::log_value("signature_depth", fc->file_signature_depth);

    if ( ConfigLogger::log_flag("block_timeout_lookup", fc->block_timeout_lookup) )
        ConfigLogger::log_value("block_timeout", fc->file_block_timeout);

    if ( ConfigLogger::log_flag("enable_capture", FileService::is_file_capture_enabled()) )
    {
        ConfigLogger::log_value("capture_memcap", fc->capture_memcap);
        ConfigLogger::log_value("capture_max_size", fc->capture_max_size);
        ConfigLogger::log_value("capture_min_size", fc->capture_min_size);
        ConfigLogger::log_value("capture_block_size", fc->capture_block_size);
    }

    ConfigLogger::log_value("lookup_timeout", fc->file_lookup_timeout);
    ConfigLogger::log_value("max_files_cached", fc->max_files_cached);
    ConfigLogger::log_value("max_files_per_flow", fc->max_files_per_flow);
    ConfigLogger::log_value("show_data_depth", fc->show_data_depth);

    ConfigLogger::log_flag("trace_type", fc->trace_type);
    ConfigLogger::log_flag("trace_signature", fc->trace_signature);
    ConfigLogger::log_flag("trace_stream", fc->trace_stream);
}

void FileInspect::show(const SnortConfig*) const
{
    if ( config )
        file_config_show(config);
}

static Module* mod_ctor()
{ return new FileIdModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void file_init()
{
    FileFlows::init();
}

static void file_term()
{
}

static Inspector* file_ctor(Module* m)
{
    FileIdModule* mod = (FileIdModule*)m;
    return new FileInspect(mod);
}

static void file_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi file_inspect_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        FILE_ID_NAME,
        FILE_ID_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_FILE,
    PROTO_BIT__NONE,
    nullptr,
    "file",
    file_init,
    file_term,
    nullptr, // tinit
    nullptr, // tterm
    file_ctor,
    file_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* sin_file_flow = &file_inspect_api.base;
