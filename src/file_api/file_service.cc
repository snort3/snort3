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
#include "file_mime_config.h"
#include "file_stats.h"
#include "file_capture.h"
#include "file_mime_process.h"
#include "file_resume_block.h"
#include "libs/file_lib.h"
#include "libs/file_config.h"

#include "main/snort_types.h"
#include "managers/action_manager.h"
#include "stream/stream_api.h"
#include "detection/detect.h"
#include "detection/detection_util.h"
#include "packet_io/active.h"
#include "framework/inspector.h"

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

static uint32_t file_config_version = 0;
static File_policy_callback_func file_policy_cb = NULL;
File_type_callback_func file_type_cb = NULL;
File_signature_callback_func file_signature_cb = NULL;
Log_file_action_func log_file_action = NULL;

/*Main File Processing functions */
static bool file_process(Flow* flow, uint8_t* file_data, int data_size,
    FilePosition position, bool upload, bool suspend_block_verdict);

/*File properties*/
static int get_file_name(Flow* flow, uint8_t** file_name, uint32_t* name_size);
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
static void set_file_action_log_callback(Log_file_action_func);

static int64_t get_max_file_depth(void);

static uint32_t str_to_hash(uint8_t* str, int length);

static void file_signature_lookup(Packet* p, bool is_retransmit);
static void file_signature_callback(Packet* p);

static inline void finish_signature_lookup(FileContext* context);
static File_Verdict get_file_verdict(Flow* flow);
static void render_block_verdict(void* ctx, Packet* p);
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
static bool check_paf_abort(Flow* flow);
static int64_t get_max_file_capture_size(Flow* flow);

FileAPI fileAPI;
FileAPI* file_api = NULL;

static void _file_signature_lookup(FileContext* context,
    Packet* p, bool is_retransmit, bool suspend_block_verdict);

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
    file_signature_callback(p);
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
    fileAPI.set_file_action_log_callback = &set_file_action_log_callback;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    fileAPI.set_log_buffers = &set_log_buffers;
    fileAPI.file_resume_block_add_file = &file_resume_block_add_file;
    fileAPI.file_resume_block_check = &file_resume_block_check;
    fileAPI.str_to_hash = &str_to_hash;
    fileAPI.file_signature_lookup = &file_signature_lookup;
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
    fileAPI.get_file_verdict = &get_file_verdict;
    fileAPI.render_block_verdict = &render_block_verdict;
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
    fileAPI.check_paf_abort = &check_paf_abort;
    fileAPI.get_max_file_capture_size = get_max_file_capture_size;

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
        file_context_free(file_session->pending_context);
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
        file_context_free(file_session->pending_context);
    }

    file_context_free(file_session->main_context);
}

static inline void init_file_context(Flow* flow, bool upload, FileContext* context)
{
    context->file_type_enabled = file_type_id_enabled;
    context->file_signature_enabled = file_signature_enabled;
    context->file_capture_enabled = file_capture_enabled;
    file_direction_set(context,upload);

    /* Check file policy to see whether we want to do either file type, file
     * signature,  or file capture
     * Note: this happen only on the start of session*/
    if (file_policy_cb)
    {
        uint32_t policy_flags = 0;
        context->app_id = stream.get_application_protocol_id(flow);

        policy_flags = file_policy_cb(flow, context->app_id, upload);

        if ( !file_type_force and !(policy_flags & ENABLE_FILE_TYPE_IDENTIFICATION) )
            context->file_type_enabled = false;

        if ( !(policy_flags & ENABLE_FILE_SIGNATURE_SHA256) )
            context->file_signature_enabled = false;

        if ( !(policy_flags & ENABLE_FILE_CAPTURE) )
            context->file_capture_enabled = false;
    }
}

FileContext* create_file_context(Flow* flow)
{
    FileSession* file_session;
    FileContext* context = file_context_create();

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
    bool upload)
{
    FileContext* context = NULL;

    FileSession* file_session = get_file_session (flow);

    /* Attempt to get a previously allocated context. */
    if (file_session)
        context  = file_session->main_context;

    if (context and ((position == SNORT_FILE_MIDDLE)or
                (position == SNORT_FILE_END)))
        return context;
    else if ((context) && (context->verdict != FILE_VERDICT_PENDING))
    {
        /* Reuse the same context */
        file_context_reset(context);
        file_stats.files_total++;
        init_file_context(flow, upload, context);
        context->file_id = file_session->max_file_id++;
        return context;
    }

    context = create_file_context(flow);
    file_session = get_file_session (flow);
    file_session->main_context = context;
    init_file_context(flow, upload, context);
    context->file_id = file_session->max_file_id++;
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

static inline void updateFileSize(FileContext* context, int data_size, FilePosition position)
{
    context->processed_bytes += data_size;
    if ((position == SNORT_FILE_END)or (position == SNORT_FILE_FULL))
    {
        if (get_max_file_depth() == (int64_t)context->processed_bytes)
            context->file_size = 0;
        else
            context->file_size = context->processed_bytes;
        context->processed_bytes = 0;
    }
}

static inline int file_eventq_add(uint32_t gid, uint32_t sid, RuleType type)
{
    return SnortEventqAdd(gid, sid, type);
}

static inline void add_file_to_block(Packet* p, File_Verdict verdict,
    uint32_t file_type_id, uint8_t* signature)
{
    uint8_t* buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    Active::drop_packet(p, true);
    DisableInspection(p);
    p->packet_flags |= PKT_FILE_EVENT_SET;

    /*Use URI as the identifier for file*/
    if (GetHttpUriData(p->flow, &buf, &len, &type))
    {
        file_sig = str_to_hash(buf, len);
        file_resume_block_add_file(p, file_sig, (uint32_t)file_config->file_block_timeout,
            verdict, file_type_id, signature);
    }
}

/*
 * Check HTTP partial content header
 * Return: 1: partial content header
 *         0: not http partial content header
 */
static inline int check_http_partial_content(Packet* p)
{
    uint8_t* buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    InspectionBuffer hb;

    if ( !p->flow or !p->flow->clouseau or
        // FIXIT-P cache id at parse time for runtime use
        !p->flow->clouseau->get_buf("http_stat_code", p, hb) )
    {
        return 0;
    }

    /*Not partial content, return*/
    if ( (hb.len != 3) or strncmp((const char*)hb.data, "206", 3) )
        return 0;

    /*Use URI as the identifier for file*/
    if (GetHttpUriData(p->flow, &buf, &len, &type))
    {
        file_sig = str_to_hash(buf, len);
        file_resume_block_check(p, file_sig);
    }

    return 1;
}

/* File signature lookup at the end of file
 * File signature callback can be used for malware lookup, file capture etc
 */
static inline void _file_signature_lookup(FileContext* context,
    Packet* pkt, bool is_retransmit, bool suspend_block_verdict)
{
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;

    if (!pkt)
    {
        finish_signature_lookup(context);
        return;
    }

    if (file_signature_cb)
    {
        verdict = file_signature_cb(pkt, pkt->flow, context->sha256,
            context->file_size, &(context->file_state), context->upload,
            context->file_id);
        file_stats.verdicts_signature[verdict]++;
    }

    if (suspend_block_verdict)
        context->suspend_block_verdict = true;

    context->verdict = verdict;

    if (verdict == FILE_VERDICT_LOG )
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
            RULE_TYPE__ALERT);
        pkt->packet_flags |= PKT_FILE_EVENT_SET;
        context->file_signature_enabled = false;
    }
    else if (verdict == FILE_VERDICT_PENDING)
    {
        /*Can't decide verdict, drop packet and waiting...*/
        if (is_retransmit)
        {
            FileConfig* file_config =  (FileConfig*)context->file_config;
            /*Drop packets if not timeout*/
            if (pkt->pkth->ts.tv_sec <= context->expires)
            {
                Active::drop_packet(pkt);
                return;
            }
            /*Timeout, let packet go through OR block based on config*/
            context->file_signature_enabled = false;
            if (file_config and file_config->block_timeout_lookup)
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                    RULE_TYPE__DROP);
            else
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                    RULE_TYPE__ALERT);
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else
        {
            FileConfig* file_config =  (FileConfig*)context->file_config;
            if (file_config)
                context->expires = (time_t)(file_config->file_lookup_timeout +
                    pkt->pkth->ts.tv_sec);
            Active::drop_packet(pkt);
            save_to_pending_context(pkt->flow);
            return;
        }
    }
    else if ((verdict == FILE_VERDICT_BLOCK)or (verdict == FILE_VERDICT_REJECT))
    {
        if (!context->suspend_block_verdict)
            render_block_verdict(context, pkt);
        context->file_signature_enabled = false;
        return;
    }

    finish_signature_lookup(context);
}

static inline void finish_signature_lookup(FileContext* context)
{
    if (context->sha256)
    {
        context->file_signature_enabled = false;
        file_stats.signatures_processed[context->file_type_id][context->upload]++;
        file_stats.signatures_by_proto[context->app_id]++;
    }
}

static File_Verdict get_file_verdict(Flow* flow)
{
    FileContext* context = get_current_file_context(flow);

    if (context == NULL)
        return FILE_VERDICT_UNKNOWN;

    return context->verdict;
}

static void render_block_verdict(void* ctx, Packet* p)
{
    FileContext* context = (FileContext*)ctx;
    Packet* pkt = (Packet*)p;

    if (p == NULL)
        return;

    if (context == NULL)
    {
        context = get_current_file_context(pkt->flow);
        if (context == NULL)
            return;
    }

    if (context->verdict == FILE_VERDICT_BLOCK)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
            RULE_TYPE__DROP);
        add_file_to_block(pkt, context->verdict, context->file_type_id,
            context->sha256);
    }
    else if (context->verdict == FILE_VERDICT_REJECT)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
            RULE_TYPE__DROP);
        ActionManager::queue_reject(pkt);
        add_file_to_block(pkt, context->verdict, context->file_type_id,
            context->sha256);
    }

    finish_signature_lookup(context);
}

static uint32_t get_file_type_id(Flow* flow)
{
    // NOTE: 'ssnptr' NULL checked in get_application_data
    FileContext* context = get_current_file_context(flow);

    if ( !context )
        return FILE_VERDICT_UNKNOWN;

    return context->file_type_id;
}

static uint32_t get_new_file_instance(Flow* flow)
{
    FileSession* file_session = get_file_session (flow);

    if (file_session)
    {
        return file_session->max_file_id++;
    }
    else
    {
        return 0;
    }
}

static void file_signature_lookup(Packet* pkt, bool is_retransmit)
{
    FileContext* context = get_current_file_context(pkt->flow);

    if (context and context->file_signature_enabled and context->sha256)
    {
        _file_signature_lookup(context, pkt, is_retransmit, false);
    }
}

static void file_signature_callback(Packet* p)
{
    /* During retransmission */
    Packet* pkt = (Packet*)p;
    Flow* flow = pkt->flow;
    FileSession* file_session;

    if (!flow)
        return;
    file_session = get_file_session (flow);
    if (!file_session)
        return;
    file_session->current_context = file_session->pending_context;
    file_signature_lookup(p, 1);
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

    if ((!context->file_type_enabled)and (!context->file_signature_enabled))
    {
        updateFileSize(context, data_size, position);
        return false;
    }

    /* if file config is changed, update it*/
    if ((context->file_config != snort_conf->file_config)or
            (context->file_config_version != file_config_version))
    {
        context->file_config = snort_conf->file_config;
        context->file_config_version = file_config_version;
        /* Reset file type context that relies on file_conf.
         * File type id will become UNKNOWN after file_type_id()
         * if in the middle of file and file type is CONTINUE (undecided) */
        context->file_type_context = NULL;
    }

    if (pkt and check_http_partial_content(pkt))
    {
        context->file_type_enabled = false;
        context->file_signature_enabled = false;
        return false;
    }

    /*file type id*/
    if (context->file_type_enabled)
    {
        File_Verdict verdict = FILE_VERDICT_UNKNOWN;

        file_type_id(context, file_data, data_size, position);

        /*Don't care unknown file type*/
        if (context->file_type_id == SNORT_FILE_TYPE_UNKNOWN)
        {
            context->file_type_enabled = false;
            context->file_signature_enabled = false;
            updateFileSize(context, data_size, position);
            file_capture_stop(context);
            return false;
        }

        if (context->file_type_id != SNORT_FILE_TYPE_CONTINUE)
        {
            if (pkt and file_type_cb)
            {
                verdict = file_type_cb(pkt, pkt->flow, context->file_type_id,
                    context->upload, context->file_id);
                file_stats.verdicts_type[verdict]++;
            }
            context->file_type_enabled = false;
            file_stats.files_processed[context->file_type_id][context->upload]++;
            file_stats.files_by_proto[context->app_id]++;
        }

        if (verdict == FILE_VERDICT_LOG )
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                RULE_TYPE__ALERT);
            context->file_signature_enabled = false;
        }
        else if (verdict == FILE_VERDICT_BLOCK)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                RULE_TYPE__DROP);
            updateFileSize(context, data_size, position);
            context->file_signature_enabled = false;
            if (pkt)
                add_file_to_block(pkt, verdict, context->file_type_id, NULL);
            return 1;
        }
        else if (verdict == FILE_VERDICT_REJECT)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                RULE_TYPE__DROP);
            if (pkt)
            {
                ActionManager::queue_reject(pkt);
                updateFileSize(context, data_size, position);
                context->file_signature_enabled = false;
                add_file_to_block(pkt, verdict, context->file_type_id, NULL);
            }
            return 1;
        }
        else if (verdict == FILE_VERDICT_STOP)
        {
            context->file_signature_enabled = false;
        }
        else if (verdict == FILE_VERDICT_STOP_CAPTURE)
        {
            file_capture_stop(context);
        }
    }

    /* file signature calculation */
    if (context->file_signature_enabled)
    {
        file_signature_sha256(context, file_data, data_size, position);
        file_stats.data_processed[context->file_type_id][context->upload]
            += data_size;
        updateFileSize(context, data_size, position);

        if ( context->sha256 and FileConfig::trace_signature )
            file_sha256_print(context->sha256);

        /*Fails to capture, when out of memory or size limit, need lookup*/
        if (context->file_capture_enabled and
            file_capture_process(context, file_data, data_size, position))
        {
            file_capture_stop(context);
            _file_signature_lookup(context, pkt, false, suspend_block_verdict);
            if (context->verdict != FILE_VERDICT_UNKNOWN)
                return 1;
        }

        /*Either get SHA or exceeding the SHA limit, need lookup*/
        if (context->file_state.sig_state != FILE_SIG_PROCESSING)
        {
            if (context->file_state.sig_state == FILE_SIG_DEPTH_FAIL)
                file_stats.files_sig_depth++;
            _file_signature_lookup(context, pkt, false, suspend_block_verdict);
        }
    }
    else
    {
        updateFileSize(context, data_size, position);
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
    /* if both disabled, return immediately*/
    if (!is_file_service_enabled())
        return false;

    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return false;

    context = find_main_file_context(flow, position, upload);

    return process_file_context(context, p, flow, file_data, data_size, position,
        suspend_block_verdict);
}

static void set_file_name(Flow* flow, uint8_t* fname, uint32_t name_size)
{
    FileContext* context = get_current_file_context(flow);
    file_name_set(context, fname, name_size);
    if ( FileConfig::trace_type )
        printFileContext(context);
}

/* Return 1: file name available,
 *        0: file name is unavailable
 */
static int get_file_name(Flow* flow, uint8_t** file_name, uint32_t* name_size)
{
    return file_name_get(get_current_file_context(flow), file_name, name_size);
}

static uint64_t get_file_size(Flow* flow)
{
    return file_size_get(get_current_file_context(flow));
}

static uint64_t get_file_processed_size(Flow* flow)
{
    FileContext* context = get_main_file_context(flow);
    if (context)
        return (context->processed_bytes);
    else
        return 0;
}

static void set_file_direction(Flow* flow, bool upload)
{
    file_direction_set(get_current_file_context(flow),upload);
}

static bool get_file_direction(Flow* flow)
{
    return file_direction_get(get_current_file_context(flow));
}

static uint8_t* get_file_sig_sha256(Flow* flow)
{
    return file_sig_sha256_get(get_current_file_context(flow));
}

static void set_file_policy_callback(File_policy_callback_func policy_func_cb)
{
    file_policy_cb = policy_func_cb;
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

    if ( callback == NULL )
    {
        file_type_force = true;
    }
    else if ( file_type_cb == NULL )
    {
        file_type_cb = callback;
    }
    else if ( file_type_cb != callback )
    {
        FatalError("Attempt to register multiple file_type callbacks.");
    }
}

/* set file signature callback function*/
static inline void _update_file_sig_callback(File_signature_callback_func cb)
{
    if (!file_signature_cb)
    {
        file_signature_cb = cb;
    }
    else if (file_signature_cb != cb)
    {
        // FIXIT-L this should be a parse warning messgae
        //WarningMessage("File service: signature callback redefined.\n");
    }
}

static void enable_file_signature(File_signature_callback_func callback)
{
    _update_file_sig_callback(callback);

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

static void set_file_action_log_callback(Log_file_action_func log_func)
{
    log_file_action = log_func;
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

/*
*  This function determines whether we shold abort PAF.  Will return
*  true if the current packet is midstream, or unestablisted session
*
*  PARAMS:
*      uint32_t - session flags passed in to callback.
*
*  RETURNS:
*      true - if we should abort paf
*      false - if we should continue using paf
*/
static bool check_paf_abort(Flow* ssn)
{
    uint32_t flags = stream.get_session_flags((Flow*)ssn);
    if (flags & SSNFLAG_MIDSTREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,
                "Aborting PAF because of midstream pickup.\n"));
        return true;
    }
    else if (!(flags & SSNFLAG_ESTABLISHED))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_FILE,
                "Aborting PAF because of unestablished session.\n"));
        return true;
    }
    return false;
}

static int64_t get_max_file_capture_size(Flow* flow)
{
    FileConfig* file_config;
    FileContext* file_context = get_current_file_context(flow);

    if (!file_context)
        return 0;

    file_config = file_context->file_config;
    return file_config->file_capture_max_size;
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

