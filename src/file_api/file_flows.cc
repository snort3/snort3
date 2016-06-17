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
/*
 ** Author(s):  Hui Cao <huica@cisco.com>
 **
 ** NOTES
 ** 8.15.15 - Initial Source Code. Hui Cao
 */

#include "file_flows.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "file_service.h"
#include "file_api.h"
#include "file_stats.h"
#include "file_capture.h"
#include "file_enforcer.h"
#include "file_policy.h"
#include "file_lib.h"
#include "file_config.h"

#include "main/snort_types.h"
#include "stream/stream_api.h"
#include "packet_io/active.h"

int64_t FileConfig::show_data_depth = DEFAULT_FILE_SHOW_DATA_DEPTH;
bool FileConfig::trace_type = false;
bool FileConfig::trace_signature = false;
bool FileConfig::trace_stream = false;

unsigned FileFlows::flow_id = 0;

FileFlows* FileFlows::get_file_flows(Flow* flow)
{
    FileFlows* fd = (FileFlows*) flow->get_application_data(FileFlows::flow_id);

    if (fd)
        return fd;

    if (FileService::is_file_service_enabled())
    {
        fd = new FileFlows(flow);
        flow->set_application_data(fd);
    }

    return fd;
}

void FileFlows::save_to_pending_context()
{
    if (pending_context != main_context)
        delete(pending_context);
    pending_context = main_context;
}

void FileFlows::set_current_file_context(FileContext* ctx)
{
    current_context = ctx;
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

void FileFlows::init_file_context(FileDirection direction, FileContext* context)
{
    FilePolicy& inspect = FileService::get_inspect();
    inspect.policy_check(flow, context);
    context->set_file_direction(direction);
}

FileContext* FileFlows::find_main_file_context(FilePosition pos, FileDirection dir, size_t index)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context = main_context;

    if (context)
    {
        if ((pos == SNORT_FILE_MIDDLE) or (pos == SNORT_FILE_END))
            return context;
        else
            delete context;
    }

    context = new FileContext;
    file_stats.files_total++;
    main_context = context;
    init_file_context(dir, context);

    if (!index)
        context->set_file_id(max_file_id++);
    else
        context->set_file_id(index);

    return context;
}

void FileFlows::finish_signature_lookup(FileContext* context)
{
    if (context->get_file_sig_sha256())
    {
        //Check file type based on file policy
        FilePolicy& inspect = FileService::get_inspect();
        inspect.signature_lookup(flow, context);
        log_file_event(context, flow);
        context->config_file_signature(false);
        file_stats.signatures_processed[context->get_file_type()][context->get_file_direction()]++;
    }
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
bool FileFlows::file_process(FileContext* context, const uint8_t* file_data,
    int data_size, FilePosition position)
{
    if ( FileConfig::trace_stream )
    {
        FileContext::print_file_data(stdout, file_data, data_size,
            snort_conf->file_config.show_data_depth);
    }

    if (!context)
        return false;

    set_current_file_context(context);
    file_stats.file_data_total += data_size;

    if ((!context->is_file_type_enabled()) and (!context->is_file_signature_enabled()))
    {
        context->update_file_size(data_size, position);
        return false;
    }

    context->set_file_config(&(snort_conf->file_config));

    if((FileService::get_file_enforcer()->cached_verdict_lookup(flow, context)
        != FILE_VERDICT_UNKNOWN))
        return true;

    /*file type id*/
    if (context->is_file_type_enabled())
    {
        context->process_file_type(file_data, data_size, position);

        /*Don't care unknown file type*/
        if (context->get_file_type()== SNORT_FILE_TYPE_UNKNOWN)
        {
            context->config_file_type(false);
            context->config_file_signature(false);
            context->update_file_size(data_size, position);
            context->stop_file_capture();
            return false;
        }

        if (context->get_file_type() != SNORT_FILE_TYPE_CONTINUE)
        {
            context->config_file_type(false);
            file_stats.files_processed[context->get_file_type()][context->get_file_direction()]++;
            //Check file type based on file policy
            FilePolicy& inspect = FileService::get_inspect();
            inspect.type_lookup(flow, context);
            log_file_event(context, flow);
        }
    }

    /* file signature calculation */
    if (context->is_file_signature_enabled())
    {
        context->process_file_signature_sha256(file_data, data_size, position);

        file_stats.data_processed[context->get_file_type()][context->get_file_direction()]
                                                            += data_size;

        context->update_file_size(data_size, position);

        if ( FileConfig::trace_signature )
            context->print_file_sha256(std::cout);

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (context->is_file_capture_enabled())
        {
            context->process_file_capture(file_data, data_size, position);
        }

        finish_signature_lookup(context);
    }
    else
    {
        context->update_file_size(data_size, position);
    }

    return true;
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
    FileDirection direction = upload ? FILE_UPLOAD:FILE_DOWNLOAD;
    /* if both disabled, return immediately*/
    if (!FileService::is_file_service_enabled())
        return false;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return false;

    context = find_main_file_context(position, direction, file_index);

    return file_process(context, file_data, data_size, position);
}

void FileFlows::set_file_name(const uint8_t* fname, uint32_t name_size)
{
    FileContext* context = get_current_file_context();
    if ( !context )
        return;

    if ( !context->get_file_name().length() )
    {
        if (fname and name_size)
            context->set_file_name((const char*)fname, name_size);
        else
            context->set_file_name(".", 1);

        log_file_event(context, flow);
    }

    if ( FileConfig::trace_type )
        context->print(std::cout);
}

void FileFlows::log_file_event(FileContext* context, Flow* flow)
{
    if ( context->get_file_name().length() )
    {
        switch (context->verdict)
        {
        case FILE_VERDICT_LOG:
            // Log file event through data bus
            get_data_bus().publish("file_event", (const uint8_t*)"LOG", 3, flow);
            break;

        case FILE_VERDICT_BLOCK:
            // can't block session inside a session
            get_data_bus().publish( "file_event", (const uint8_t*)"BLOCK", 5, flow);
            break;

        case FILE_VERDICT_REJECT:
            get_data_bus().publish( "file_event", (const uint8_t*)"RESET", 5, flow);
            break;
        default:
            break;
        }
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


