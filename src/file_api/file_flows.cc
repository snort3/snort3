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

#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"

#include "file_cache.h"
#include "file_config.h"
#include "file_lib.h"
#include "file_service.h"

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

void FileFlows::handle_retransmit (Packet*)
{
    if (file_policy == nullptr)
        return;

    FileContext* file = get_file_context(pending_file_id, false);
    if ((file == nullptr) or (file->verdict != FILE_VERDICT_PENDING))
        return;

    FileVerdict verdict = file_policy->signature_lookup(flow, file);
    FileCache* file_cache = FileService::get_file_cache();
    if (file_cache)
        file_cache->apply_verdict(flow, file, verdict, false, file_policy);
    file->log_file_event(flow, file_policy);
}

FileFlows* FileFlows::get_file_flows(Flow* flow)
{

    FileFlows* fd = (FileFlows*)flow->get_flow_data(FileFlows::file_flow_data_id);

    if (fd)
        return fd;

    FileInspect* fi = (FileInspect*)InspectorManager::get_inspector(FILE_ID_NAME, true);

    if (FileService::is_file_service_enabled() and fi)
    {
        fd = new FileFlows(flow, fi);
        flow->set_flow_data(fd);
    }
    else
        return fd;

    FileConfig* fc = fi->config;
    if (fc and fd)
    {
        fd->set_file_policy(&(fc->get_file_policy()));
    }

    return fd;
}

FilePolicyBase* FileFlows::get_file_policy(Flow* flow)
{
    FileFlows* fd = (FileFlows*)flow->get_flow_data(FileFlows::file_flow_data_id);

    if (fd)
        return fd->get_file_policy(flow);

    return nullptr;
}

void FileFlows::set_current_file_context(FileContext* ctx)
{
    current_context = ctx;
}

FileContext* FileFlows::get_current_file_context()
{
    if (current_file_id)
    {
        return get_file_context(current_file_id, false);
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
    delete(main_context);
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
        context->set_file_id(get_new_file_instance());
    else
        context->set_file_id(index);

    return context;
}

FileContext* FileFlows::get_file_context(uint64_t file_id, bool to_create)
{
    // search for file based on id to support multiple files
    FileCache* file_cache = FileService::get_file_cache();
    assert(file_cache);

    FileContext* context = file_cache->get_file(flow, file_id, to_create);
    current_file_id = file_id;
    return context;
}

/* This function is used to process file that is sent in pieces
 *
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileFlows::file_process(uint64_t file_id, const uint8_t* file_data,
    int data_size, uint64_t offset, FileDirection dir)
{
    int64_t file_depth = FileService::get_max_file_depth();

    if ((file_depth < 0)or (offset > (uint64_t)file_depth))
    {
        return false;
    }

    FileContext* context = get_file_context(file_id, true);

    if (!context)
        return false;

    if (!context->get_processed_bytes())
    {
        context->check_policy(flow, dir, file_policy);
        context->set_file_id(file_id);
    }

    if (context->verdict != FILE_VERDICT_UNKNOWN)
    {
        /*A new file session, but policy might be different*/
        context->check_policy(flow, dir, file_policy);

        if ((context->get_file_sig_sha256())
            || !context->is_file_signature_enabled())
        {
            /* Just check file type and signature */
            FilePosition position = SNORT_FILE_FULL;
            return context->process(flow, file_data, data_size, position, file_policy);
        }
    }

    return context->process(flow, file_data, data_size, offset, file_policy);
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileFlows::file_process(const uint8_t* file_data, int data_size,
    FilePosition position, bool upload, size_t file_index)
{
    FileContext* context;
    FileDirection direction = upload ? FILE_UPLOAD : FILE_DOWNLOAD;
    /* if both disabled, return immediately*/
    if (!FileService::is_file_service_enabled())
        return false;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return false;

    context = find_main_file_context(position, direction, file_index);

    set_current_file_context(context);

    context->set_signature_state(gen_signature);
    return context->process(flow, file_data, data_size, position, file_policy);
}

void FileFlows::set_file_name(const uint8_t* fname, uint32_t name_size)
{
    FileContext* context = get_current_file_context();
    if ( !context )
        return;

    if ( !context->is_file_name_set() )
    {
        if (fname and name_size)
            context->set_file_name((const char*)fname, name_size);

        context->log_file_event(flow, file_policy);
    }
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
    IT_PASSIVE,
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

