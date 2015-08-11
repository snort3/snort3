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
** Author(s):  Hui Cao <huica@cisco.com>
**
** NOTES
** 5.25.12 - Initial Source Code. Hui Cao
*/

#include "file_service.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "file_api.h"
#include "file_stats.h"
#include "file_capture.h"
#include "file_resume_block.h"
#include "libs/file_lib.h"
#include "libs/file_config.h"

#include "mime/file_mime_config.h"
#include "mime/file_mime_process.h"
#include "main/snort_types.h"
#include "managers/action_manager.h"
#include "stream/stream_api.h"
#include "detection/detect.h"
#include "detection/detection_util.h"
#include "packet_io/active.h"
#include "framework/inspector.h"

int64_t FileConfig::show_data_depth = DEFAULT_FILE_SHOW_DATA_DEPTH;
bool FileConfig::trace_type = false;
bool FileConfig::trace_signature = false;
bool FileConfig::trace_stream = false;
typedef struct _FileSession
{
    FileContext* current_context;
    FileContext* main_context;
    FileContext* pending_context;
    uint32_t max_file_id;
} FileSession;

static bool file_type_id_enabled = false;
static bool file_signature_enabled = false;
static bool file_capture_enabled = false;
static bool file_processing_initiated = false;

/*Main File Processing functions */
static bool file_process(Flow* flow, uint8_t* file_data, int data_size,
    FilePosition position, bool upload, bool suspend_block_verdict);

/*File properties*/
static bool get_file_name(Flow* flow, uint8_t** file_name, uint32_t* name_size);
static uint64_t get_file_processed_size(Flow* flow);

static void set_file_name(Flow* flow, uint8_t* file_name, uint32_t name_size);

static void enable_file_type();
static void enable_file_signature ();
static void enable_file_capture();

static int64_t get_max_file_depth(void);

static inline void finish_signature_lookup(FileContext* context);

static FilePosition get_file_position(Packet* pkt);
static bool is_file_service_enabled(void);
static uint32_t get_file_type_id(Flow* flow);
static uint32_t get_new_file_instance(Flow* flow);

/* File context based file processing*/
FileContext* create_file_context(Flow* flow);
bool set_current_file_context(Flow* flow, FileContext* ctx);
FileContext* get_main_file_context(Flow* flow);
static bool process_file_context(FileContext* ctx, Flow* flow, uint8_t* file_data,
    int data_size, FilePosition position);
static FilePosition get_file_position(Packet* pkt);

FileAPI fileAPI;
FileAPI* file_api = NULL;

static void file_session_free(FileSession* file_session);

class FileFlowData : public FlowData
{
public:
    FileFlowData() : FlowData(flow_id)
    { memset(&session, 0, sizeof(session)); }

    ~FileFlowData()
    { file_session_free(&session); }

    static void init()
    { flow_id = FlowData::get_flow_id(); }

    //void handle_retransmit(Packet*) override;

public:
    static unsigned flow_id;
    FileSession session;
};

unsigned FileFlowData::flow_id = 0;

void init_fileAPI(void)
{
    fileAPI.version = FILE_API_VERSION;
    fileAPI.is_file_service_enabled = &is_file_service_enabled;
    fileAPI.file_process = &file_process;
    fileAPI.get_file_name = &get_file_name;
    fileAPI.get_file_processed_size = &get_file_processed_size;
    fileAPI.set_file_name = &set_file_name;
    fileAPI.enable_file_type = &enable_file_type;
    fileAPI.enable_file_signature = &enable_file_signature;
    fileAPI.enable_file_capture = &enable_file_capture;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    fileAPI.get_file_type_id = &get_file_type_id;

    fileAPI.get_file_position = &get_file_position;

    file_api = &fileAPI;
    MimeSession::init();
    FileFlowData::init();
}

void FileAPIPostInit(void)
{
    FileConfig* file_config = (FileConfig*)(snort_conf->file_config);

    if (file_type_id_enabled or file_signature_enabled or file_capture_enabled)
    {
        if (!file_config)
        {
            file_config =  new FileConfig;
            snort_conf->file_config = file_config;
        }
    }

    if ( file_capture_enabled)
        FileCapture::init_mempool(file_config->file_capture_memcap,
            file_config->file_capture_block_size);
}

static void start_file_processing(void)
{
    if (!file_processing_initiated)
    {
        file_resume_block_init();
        //RegisterProfileStats("file", print_file_stats);  FIXIT-M put in module
        file_processing_initiated = true;
    }
}

void close_fileAPI(void)
{
    file_resume_block_cleanup();
    MimeSession::exit();
    FileCapture::exit();
}

static inline FileSession* get_file_session(Flow* flow)
{
    FileFlowData* p = (FileFlowData*)flow->get_application_data(FileFlowData::flow_id);
    return p ? &p->session : NULL;
}

FileContext* get_current_file_context(Flow* flow)
{
    FileSession* file_session = get_file_session (flow);

    if (file_session)
        return file_session->current_context;
    else
        return NULL;
}
uint16_t   app_id;
FileContext* get_main_file_context(Flow* flow)
{
    FileSession* file_session = get_file_session (flow);

    if (file_session)
        return file_session->main_context;
    else
        return NULL;
}

static inline void save_to_pending_context(Flow* flow)
{
    FileSession* file_session = get_file_session (flow);

    if (file_session->pending_context != file_session->main_context)
        delete(file_session->pending_context);
    file_session->pending_context = file_session->main_context;
}

bool set_current_file_context(Flow* flow, FileContext* ctx)
{
    FileSession* file_session = get_file_session (flow);

    if (!file_session)
    {
        return false;
    }

    file_session->current_context = ctx;
    return true;
}

static void file_session_free(FileSession* file_session)
{
    if (!file_session)
        return;

    /*Clean up all the file contexts*/
    if ( file_session->pending_context and
            (file_session->main_context != file_session->pending_context))
    {
        delete(file_session->pending_context);
    }

    delete(file_session->main_context);
}

static inline void init_file_context(FileDirection direction, FileContext* context)
{
    context->config_file_type(file_type_id_enabled);
    context->config_file_signature(file_signature_enabled);
    context->config_file_capture(file_capture_enabled);
    context->set_file_direction(direction);
}

FileContext* create_file_context(Flow* flow)
{
    FileSession* file_session;
    FileContext* context = new FileContext;

    /* Create file session if not yet*/
    file_session = get_file_session (flow);

    if (!file_session)
    {
        FileFlowData* ffd = new FileFlowData;
        flow->set_application_data(ffd);
    }

    file_stats.files_total++;
    return context;
}

static inline FileContext* find_main_file_context(Flow* flow, FilePosition position,
    FileDirection direction)
{
    FileContext* context = NULL;

    FileSession* file_session = get_file_session (flow);

    /* Attempt to get a previously allocated context. */
    if (file_session)
        context  = file_session->main_context;

    if (context)
    {
        if ((position == SNORT_FILE_MIDDLE) or (position == SNORT_FILE_END))
            return context;
        else
            delete context;
    }

    context = create_file_context(flow);
    file_session = get_file_session (flow);
    file_session->main_context = context;
    init_file_context(direction, context);
    context->set_file_id(file_session->max_file_id++);
    return context;
}

static void DumpHex(FILE* fp, const uint8_t* data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    if (file_config->show_data_depth < (int64_t)len)
        len = file_config->show_data_depth;

    fprintf(fp,"Show length: %d \n", len);
    for (i=0, pos=0; i<len; i++, pos++)
    {
        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) and (c == ' ' or !isspace(c)))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos)
    {
        str[pos] = 0;
        for (; pos < 17; pos++)
        {
            if (pos == 8)
            {
                str[pos] = ' ';
                pos++;
                fprintf(fp, "%s", "    ");
            }
            else
            {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}

static inline void finish_signature_lookup(FileContext* context)
{
    if (context->get_file_sig_sha256())
    {
        context->config_file_signature(false);
        file_stats.signatures_processed[context->get_file_type()][context->get_file_direction()]++;
    }
}

static uint32_t get_file_type_id(Flow* flow)
{
    FileContext* context = get_current_file_context(flow);

    if ( !context )
        return SNORT_FILE_TYPE_UNKNOWN;

    return context->get_file_type();
}

static uint64_t get_file_processed_size(Flow* flow)
{
    FileContext* context = get_current_file_context(flow);

    if ( !context )
        return 0;

    return context->get_processed_bytes();
}

static uint32_t get_new_file_instance(Flow* flow)
{
    FileSession* file_session = get_file_session (flow);

    if (file_session)
        return file_session->max_file_id++;
    else
        return 0;
}

static bool is_file_service_enabled()
{
    return (file_type_id_enabled or file_signature_enabled);
}

/*
 * Return:
 *    true: continue processing/log/block this file
 *    false: ignore this file
 */
static bool process_file_context(FileContext* context, Flow* flow, uint8_t* file_data,
        int data_size, FilePosition position)
{
    if ( FileConfig::trace_stream )
    {
        DumpHex(stdout, file_data, data_size);
    }

    if (!context)
        return false;

    set_current_file_context(flow, context);
    file_stats.file_data_total += data_size;

    if ((!context->is_file_type_enabled()) and (!context->is_file_signature_enabled()))
    {
        context->update_file_size(data_size, position);
        return false;
    }

    context->set_file_config(snort_conf->file_config);

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
            context->print_file_sha256();

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
static bool file_process(Flow* flow, uint8_t* file_data, int data_size,
    FilePosition position, bool upload, bool suspend_block_verdict)
{
    FileContext* context;
    FileDirection direction = upload ? FILE_UPLOAD:FILE_DOWNLOAD;
    /* if both disabled, return immediately*/
    if (!is_file_service_enabled())
        return false;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return false;

    context = find_main_file_context(flow, position, direction);

    return process_file_context(context, flow, file_data, data_size, position);
}

static void set_file_name(Flow* flow, uint8_t* fname, uint32_t name_size)
{
    FileContext* context = get_current_file_context(flow);
    if (context)
        context->set_file_name(fname, name_size);
    if ( FileConfig::trace_type )
        context->print();
}

/* Return true: file name available,
 *        false: file name is unavailable
 */
static bool get_file_name(Flow* flow, uint8_t** file_name, uint32_t* name_size)
{
    FileContext* context = get_current_file_context(flow);
    if (context)
        return context->get_file_name(file_name, name_size);
    else
        return false;
}

/*
 * - Only accepts 1 (ONE) callback being registered.
 *
 * - Call with NULL callback to "force" (guarantee) file type identification.
 *
 * TBD: Remove per-context "file_type_enabled" checking to simplify implementation.
 *
 */
static void enable_file_type()
{
    if (!file_type_id_enabled)
    {
        file_type_id_enabled = true;
        start_file_processing();
    }
}

static void enable_file_signature()
{

    if (!file_signature_enabled)
    {
        file_signature_enabled = true;
        start_file_processing();
    }
}

/* Enable file capture, also enable file signature */
static void enable_file_capture()
{
    if (!file_capture_enabled)
    {
        file_capture_enabled = true;
        enable_file_signature();
    }
}

/* Get maximal file depth based on configuration
 * This function must be called after all file services are configured/enabled.
 */
static int64_t get_max_file_depth(void)
{
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    if (!file_config)
        return -1;

    if (file_config->file_depth)
        return file_config->file_depth;

    file_config->file_depth = -1;

    if (file_type_id_enabled)
    {
        file_config->file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled)
    {
        if (file_config->file_signature_depth > file_config->file_depth)
            file_config->file_depth = file_config->file_signature_depth;
    }

    if (file_config->file_depth > 0)
    {
        /*Extra byte for deciding whether file data will be over limit*/
        file_config->file_depth++;
        return (file_config->file_depth);
    }
    else
    {
        return -1;
    }
}

static FilePosition get_file_position(Packet* pkt)
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
