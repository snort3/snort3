//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "managers/inspector_manager.h"
#include "protocols/packet.h"

#include "file_cache.h"
#include "file_config.h"
#include "file_lib.h"
#include "file_service.h"

unsigned FileFlows::file_flow_data_id = 0;

FileFlows* FileFlows::get_file_flows(Flow* flow)
{

    FileFlows* fd = (FileFlows*)flow->get_flow_data(FileFlows::file_flow_data_id);

    if (fd)
        return fd;

    if (FileService::is_file_service_enabled())
    {
        fd = new FileFlows(flow);
        flow->set_flow_data(fd);
    }

    return fd;
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

uint32_t FileFlows::get_new_file_instance()
{
    return max_file_id++;
}

FileFlows::~FileFlows()
{
    /*Clean up all the file contexts*/
    if ( pending_context and (main_context != pending_context))
    {
        delete(pending_context);
    }

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
    context->check_policy(flow, dir);

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

    FileCache::FileHashKey key;
    key.dip.set(flow->client_ip);
    key.sip.set(flow->server_ip);
    key.padding = 0;
    key.file_sig = file_id;

    FileContext* context = file_cache->find(key);

    if (!context && to_create)
        context = file_cache->add(key);

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
    int ret = 0;

    int64_t file_depth = FileService::get_max_file_depth();

    if ((file_depth < 0)or (offset > (uint64_t)file_depth))
    {
        return 0;
    }

    FileContext* context = get_file_context(file_id, true);

    if (!context)
        return 0;

    if (!context->get_processed_bytes())
    {
        context->check_policy(flow, dir);
        context->set_file_id(file_id);
    }

    if (context->verdict != FILE_VERDICT_UNKNOWN)
    {
        /*A new file session, but policy might be different*/
        context->check_policy(flow, dir);

        if ((context->get_file_sig_sha256())
            || !context->is_file_signature_enabled())
        {
            /* Just check file type and signature */
            FilePosition position = SNORT_FILE_FULL;
            ret = context->process(flow, file_data, data_size, position);
            return ret;
        }
    }

    return context->process(flow, file_data, data_size, offset);
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
    return context->process(flow, file_data, data_size, position);
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

        context->log_file_event(flow);
    }
}

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

FileInspect::FileInspect(FileIdModule* fm)
{
    fm->load_config(config);
}

FileInspect:: ~FileInspect()
{
    if (config)
        delete config;
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
    (uint16_t)PktType::NONE,
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

