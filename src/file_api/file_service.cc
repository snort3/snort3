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

#include "snort_types.h"
#include "file_api.h"
#include "libs/file_lib.h"
#include "libs/file_config.h"
#include "file_mime_config.h"
#include "file_stats.h"
#include "managers/action_manager.h"
#include "stream/stream_api.h"
#include "detect.h"
#include "packet_io/active.h"
#include "file_capture.h"
#include "file_mime_process.h"
#include "file_resume_block.h"
#include "framework/inspector.h"
#include "detection_util.h"

// FIXIT-M bad dependency; use inspector::get_buf()
#include "service_inspectors/http_inspect/hi_main.h"

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
static bool file_type_force = false;

/*Main File Processing functions */
static bool file_process(Flow* flow, uint8_t* file_data, int data_size,
    FilePosition position, bool upload, bool suspend_block_verdict);

/*File properties*/
static bool get_file_name(Flow* flow, uint8_t** file_name, uint32_t* name_size);
static uint64_t get_file_size(Flow* flow);
static uint64_t get_file_processed_size(Flow* flow);
static bool get_file_direction(Flow* flow);
static uint8_t* get_file_sig_sha256(Flow* flow);

static void set_file_name(Flow* flow, uint8_t* file_name, uint32_t name_size);
static void set_file_direction(Flow* flow, bool upload);

static void set_file_policy_callback(File_policy_callback_func);
static void enable_file_type(File_type_callback_func);
static void enable_file_signature (File_signature_callback_func);
static void enable_file_capture(File_signature_callback_func);

static int64_t get_max_file_depth(void);

static uint32_t str_to_hash(uint8_t* str, int length);

static inline void finish_signature_lookup(FileContext* context);

static FilePosition get_file_position(Packet* pkt);
static bool is_file_service_enabled(void);
static uint32_t get_file_type_id(Flow* flow);
static uint32_t get_new_file_instance(Flow* flow);

/* File context based file processing*/
FileContext* create_file_context(Flow* flow);
bool set_current_file_context(Flow* flow, FileContext* ctx);
FileContext* get_main_file_context(Flow* flow);
static bool process_file_context(FileContext* ctx, Packet* p, Flow* flow, uint8_t* file_data,
    int data_size, FilePosition position, bool suspend_block_verdict);
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

    void handle_retransmit(Packet*) override;

public:
    static unsigned flow_id;
    FileSession session;
};

unsigned FileFlowData::flow_id = 0;

void FileFlowData::handle_retransmit(Packet* p)
{
    //file_signature_callback(p);
}

void init_fileAPI(void)
{
    fileAPI.version = FILE_API_VERSION;
    fileAPI.is_file_service_enabled = &is_file_service_enabled;
    fileAPI.file_process = &file_process;
    fileAPI.get_file_name = &get_file_name;
    fileAPI.get_file_size = &get_file_size;
    fileAPI.get_file_processed_size = &get_file_processed_size;
    fileAPI.get_file_direction = &get_file_direction;
    fileAPI.get_sig_sha256 = &get_file_sig_sha256;
    fileAPI.set_file_name = &set_file_name;
    fileAPI.set_file_direction = &set_file_direction;
    fileAPI.set_file_policy_callback = &set_file_policy_callback;
    fileAPI.enable_file_type = &enable_file_type;
    fileAPI.enable_file_signature = &enable_file_signature;
    fileAPI.enable_file_capture = &enable_file_capture;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    fileAPI.set_log_buffers = &set_log_buffers;
    fileAPI.file_resume_block_add_file = &file_resume_block_add_file;
    fileAPI.file_resume_block_check = &file_resume_block_check;
    fileAPI.str_to_hash = &str_to_hash;
    fileAPI.set_mime_decode_config_defauts = &set_mime_decode_config_defauts;
    fileAPI.set_mime_log_config_defauts = &set_mime_log_config_defauts;
    fileAPI.parse_mime_decode_args = &parse_mime_decode_args;
    fileAPI.check_decode_config = &check_decode_config;
    fileAPI.process_mime_data = &process_mime_data;
    fileAPI.free_mime_session = &free_mime_session;
    fileAPI.is_decoding_enabled = &is_decoding_enabled;
    fileAPI.is_decoding_conf_changed = &is_decoding_conf_changed;
    fileAPI.is_mime_log_enabled = &is_mime_log_enabled;
    fileAPI.finalize_mime_position = &finalize_mime_position;
    fileAPI.reserve_file = &file_capture_reserve;
    fileAPI.read_file = &file_capture_read;
    fileAPI.release_file = &file_capture_release;
    fileAPI.get_file_capture_size = &file_capture_size;
    fileAPI.get_file_type_id = &get_file_type_id;
    fileAPI.get_new_file_instance = &get_new_file_instance;

    fileAPI.create_file_context = &create_file_context;
    fileAPI.set_current_file_context = &set_current_file_context;
    fileAPI.get_current_file_context = &get_current_file_context;
    fileAPI.get_main_file_context = &get_main_file_context;
    fileAPI.get_file_position = &get_file_position;
    fileAPI.reset_mime_paf_state = &reset_mime_paf_state;
    fileAPI.process_mime_paf_data = &process_mime_paf_data;
    fileAPI.check_data_end = check_data_end;

    file_api = &fileAPI;
    init_mime();
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
        file_capture_init_mempool(file_config->file_capture_memcap,
            file_config->file_capture_block_size);

    //file_sevice_reconfig_set(false);
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
    free_mime();
    file_caputure_close();
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
static bool process_file_context(FileContext* context, Packet* pkt, Flow* flow, uint8_t* file_data,
        int data_size, FilePosition position, bool suspend_block_verdict)
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
        context->updateFileSize(data_size, position);
        return false;
    }

    /*file type id*/
    if (context->is_file_type_enabled())
    {
        context->file_type_eval(file_data, data_size, position);

        /*Don't care unknown file type*/
        if (context->get_file_type()== SNORT_FILE_TYPE_UNKNOWN)
        {
            context->config_file_type(false);
            context->config_file_signature(false);
            context->updateFileSize(data_size, position);
            file_capture_stop(context);
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
        context->file_signature_sha256_eval(file_data, data_size, position);

        file_stats.data_processed[context->get_file_type()][context->get_file_direction()]
            += data_size;

        context->updateFileSize(data_size, position);

        if ( FileConfig::trace_signature )
            context->print_file_sha256();

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (context->is_file_capture_enabled() and
            file_capture_process(context, file_data, data_size, position))
        {
            file_capture_stop(context);
            return 1;
        }
    }
    else
    {
        context->updateFileSize(data_size, position);
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
    Packet* p = NULL;
    FileDirection direction = upload ? FILE_UPLOAD:FILE_DOWNLOAD;
    /* if both disabled, return immediately*/
    if (!is_file_service_enabled())
        return false;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return false;

    context = find_main_file_context(flow, position, direction);

    return process_file_context(context, p, flow, file_data, data_size, position,
        suspend_block_verdict);
}

static void set_file_name(Flow* flow, uint8_t* fname, uint32_t name_size)
{
    FileContext* context = get_current_file_context(flow);
    if (context)
        context->set_file_name(fname, name_size);
    if ( FileConfig::trace_type )
        printFileContext(context);
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
static void enable_file_type(File_type_callback_func callback)
{
    if (!file_type_id_enabled)
    {
        file_type_id_enabled = true;
        //  file_sevice_reconfig_set(true);
        start_file_processing();
        // FIXIT-L snort++ does not yet output startup configuration
        //LogMessage("File service: file type enabled.\n");
    }
}

static void enable_file_signature(File_signature_callback_func callback)
{

    if (!file_signature_enabled)
    {
        file_signature_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        start_file_processing();
        //LogMessage("File service: file signature enabled.\n");
    }
}

/* Enable file capture, also enable file signature */
static void enable_file_capture(File_signature_callback_func callback)
{
    if (!file_capture_enabled)
    {
        file_capture_enabled = true;
#ifdef SNORT_RELOAD
        file_sevice_reconfig_set(true);
#endif
        //LogMessage("File service: file capture enabled.\n");
        /* Enable file signature*/
        enable_file_signature(callback);
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

static uint32_t str_to_hash(uint8_t* str, int length)
{
    uint32_t a,b,c,tmp;
    int i,j,k,l;
    a = b = c = 0;
    for (i=0,j=0; i<length; i+=4)
    {
        tmp = 0;
        k = length - i;
        if (k > 4)
            k=4;

        for (l=0; l<k; l++)
        {
            tmp |= *(str + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j = 0;
        }
    }
    final (a,b,c);
    return c;
}

