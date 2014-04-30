/*
 **
 **
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 **  Copyright (C) 2012-2013 Sourcefire, Inc.
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  5.25.12 - Initial Source Code. Hui Cao
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
#include "libs/file_config.h"
#include "file_mime_config.h"

#include "stream5/stream_api.h"
#include "mstring.h"
#include "detect.h"
#include "fpdetect.h"
#include "packet_io/active.h"

#include "file_mime_process.h"
#include "file_resume_block.h"
#include "service_inspectors/http_inspect/hi_main.h"  // FIXIT bad dependency
#include "detection_util.h"

#include "target_based/sftarget_protocol_reference.h"
#include "target_based/sftarget_reader.h"

static bool file_type_id_enabled = false;  // FIXIT 1 / process
static bool file_signature_enabled = false;
static bool file_processing_initiated = false;

static Get_file_policy_func get_file_policy = NULL;
File_type_done_func  file_type_done = NULL;
File_signature_done_func file_signature_done = NULL;
Log_file_action_func log_file_action = NULL;

/*Main File Processing functions */
static int file_process(
    void*, uint8_t* file_data, int data_size, FilePosition position,
    bool upload, bool suspend_block_verdict);

/*File properties*/
static int get_file_name (Flow* flow, uint8_t **file_name, uint32_t *name_size);
static uint64_t get_file_size(Flow* flow);
static uint64_t get_file_processed_size(Flow* flow);
static bool get_file_direction(Flow* flow);
static uint8_t *get_file_sig_sha256(Flow* flow);

static void set_file_name(Flow* flow, uint8_t * file_name, uint32_t name_size);
static void set_file_direction(Flow* flow, bool upload);

static void set_file_policy_callback(Get_file_policy_func);
static void enable_file_type(File_type_done_func );
static void enable_file_signature (File_signature_done_func);
static void set_file_action_log_callback(Log_file_action_func);

static int64_t get_max_file_depth(void);

static void set_file_name_from_log(FILE_LogState *log_state, void *ssn);

static uint32_t str_to_hash(uint8_t *str, int length );

static void file_signature_lookup(void* p, bool is_retransmit);
static void file_signature_callback(Packet* p);

//static void print_file_stats(int exiting);

static inline void finish_signature_lookup(FileContext *context, Flow *flow);
static File_Verdict get_file_verdict(Flow *flow);
static void render_block_verdict(void *ctx, void *p);

FileAPI fileAPI;
FileAPI* file_api = NULL;

static unsigned s_cb_id = 0;  // FIXIT 1 / process

typedef struct _File_Stats {

    uint64_t files_total;
    uint64_t files_processed[FILE_ID_MAX + 1][2];
    uint64_t signatures_processed[FILE_ID_MAX + 1][2];
    uint64_t verdicts_type[FILE_VERDICT_MAX];
    uint64_t verdicts_signature[FILE_VERDICT_MAX];
    uint64_t files_processed_by_proto[MAX_PROTOCOL_ORDINAL + 1];
    uint64_t signatures_processed_by_proto[MAX_PROTOCOL_ORDINAL + 1];

} FileStats;

static THREAD_LOCAL_TBD FileStats file_stats;

static void cleanDynamicContext(FileContext*);

class FileFlowData : public FlowData
{
public:
    FileFlowData() : FlowData(flow_id)
    { memset(&context, 0, sizeof(context)); };

    ~FileFlowData()
    { cleanDynamicContext(&context); };

    static void init()
    { flow_id = FlowData::get_flow_id(); };

public:
    static unsigned flow_id;
    FileContext context;
};

unsigned FileFlowData::flow_id = 0;

void FileAPIInit(void)
{
    fileAPI.version = FILE_API_VERSION5;
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
    fileAPI.set_file_action_log_callback = &set_file_action_log_callback;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    fileAPI.log_file_name = &log_file_name;
    fileAPI.set_file_name_from_log = &set_file_name_from_log;
    fileAPI.set_log_buffers = &set_log_buffers;
    fileAPI.init_mime_mempool = &init_mime_mempool;
    fileAPI.init_log_mempool=  &init_log_mempool;
    fileAPI.file_resume_block_add_file = &file_resume_block_add_file;
    fileAPI.file_resume_block_check = &file_resume_block_check;
    fileAPI.str_to_hash = &str_to_hash;
    fileAPI.file_signature_lookup = &file_signature_lookup;
    fileAPI.set_mime_decode_config_defauts = &set_mime_decode_config_defauts;
    fileAPI.set_mime_log_config_defauts = &set_mime_log_config_defauts;
    fileAPI.parse_mime_decode_args = &parse_mime_decode_args;
    fileAPI.process_mime_data = &process_mime_data;
    fileAPI.free_mime_session = &free_mime_session;
    fileAPI.is_decoding_enabled = &is_decoding_enabled;
    fileAPI.is_decoding_conf_changed = &is_decoding_conf_changed;
    fileAPI.is_mime_log_enabled = &is_mime_log_enabled;
    fileAPI.finalize_mime_position = &finalize_mime_position;
    fileAPI.get_file_verdict = &get_file_verdict;
    fileAPI.render_block_verdict = &render_block_verdict;
    file_api = &fileAPI;
    init_mime();
    FileFlowData::init();
}

void FileAPIPostInit (void)
{
    if ( file_signature_enabled )
        s_cb_id = stream.register_event_handler(file_signature_callback);
}

static void start_file_processing(void)
{
    if (!file_processing_initiated)
    {
        file_resume_block_init();
        //RegisterPreprocStats("file", print_file_stats);  FIXIT not a preproc !
        file_processing_initiated = true;
    }
}
void free_file_config(void *conf)
{

    free_file_rules(conf);
    free_file_identifiers(conf);
    free(conf);
}

void close_fileAPI(void)
{
    file_resume_block_cleanup();
    free_mime();
}

/*File context management*/
static void cleanDynamicContext (FileContext *context)
{
    if (context->file_signature_context)
        free(context->file_signature_context);
    if(context->sha256)
        free(context->sha256);
}
void file_context_reset(FileContext *context)
{
    cleanDynamicContext(context);
    memset(context, 0, sizeof(*context));
}

static FileContext* get_file_context(Flow* f)
{
    FileFlowData* p = (FileFlowData*)f->get_application_data(
        FileFlowData::flow_id);

    return p ? &p->context : NULL;
}

static FileContext* get_file_context(void* p, FilePosition position, bool upload)
{
    Packet *pkt = (Packet *)p;

    /* Attempt to get a previously allocated context. */
    FileContext* context = get_file_context(pkt->flow);

    if (context && ((position == SNORT_FILE_MIDDLE) || (position == SNORT_FILE_END)))
        return context;

    else if (!context)
    {
        FileFlowData* ffd = new FileFlowData;
        context = &ffd->context;
	    pkt->flow->set_application_data(ffd);
        file_stats.files_total++;
    }
    else
    {
        /*Push file event when there is another file in the same packet*/
        if (pkt->packet_flags & PKT_FILE_EVENT_SET)
        {
            SnortEventqLog(pkt);
            SnortEventqReset();
            pkt->packet_flags &= ~PKT_FILE_EVENT_SET;
        }
        file_context_reset(context);
        file_stats.files_total++;
    }
    context->file_type_enabled = file_type_id_enabled;
    context->file_signature_enabled = file_signature_enabled;
    /*Check file policy to see whether we want to do either file type or file signature
     * Note: this happen only on the start of session*/
    if (get_file_policy)
    {
        int app_id;
        uint32_t policy_flags = 0;
        app_id = stream.get_application_protocol_id(pkt->flow);
        policy_flags = get_file_policy(pkt->flow, (int16_t)app_id, upload);
        if (!(policy_flags & ENABLE_FILE_TYPE_IDENTIFICATION))
            context->file_type_enabled = false;
        if (!(policy_flags & ENABLE_FILE_SIGNATURE_SHA256))
            context->file_signature_enabled = false;
    }
    return context;
}

#if defined(DEBUG_MSGS) || defined (REG_TEST)
#define MAX_CONTEXT_INFO_LEN 1024
static void printFileContext (FileContext* context)
{
    char buf[MAX_CONTEXT_INFO_LEN + 1];
    int unused;
    char *cur = buf;
    int used = 0;

    if (!context)
    {
        printf("File context is NULL.\n");
        return;
    }
    unused = sizeof(buf) - 1;
    used = snprintf(cur, unused, "File name: ");

    if (used < 0)
    {
        printf("Fail to output file context\n");
        return;
    }
    unused -= used;
    cur += used;

    if ((context->file_name_size > 0) && (unused > (int) context->file_name_size))
    {
        strncpy(cur, (char *)context->file_name, context->file_name_size );
        unused -= context->file_name_size;
        cur += context->file_name_size;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile type: %s(%d)",
                file_info_from_ID(context->file_config, context->file_type_id), context->file_type_id);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile size: %u",
                (unsigned int)context->file_size);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nProcessed size: %u\n",
                (unsigned int)context->processed_bytes);
        unused -= used;
        cur += used;
    }

    buf[sizeof(buf) - 1] = '\0';
    printf("%s", buf);
}

static void DumpHex(FILE *fp, const uint8_t *data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

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
        if (isprint(c) && (c == ' ' || !isspace(c)))
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
#endif

static inline void updateFileSize(FileContext* context, int data_size, FilePosition position)
{
    context->processed_bytes += data_size;
    if ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL))
    {
        context->file_size = context->processed_bytes;
        context->processed_bytes = 0;
    }
}

static inline int file_eventq_add(uint32_t gid, uint32_t sid, const char*, RuleType type)
{
    return SnortEventqAdd(gid, sid, type);
}

static inline void add_file_to_block(Packet *p, File_Verdict verdict,
        uint32_t file_type_id, uint8_t *signature)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

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
static inline int check_http_partial_content(Packet *p)
{
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint32_t type = 0;
    uint32_t file_sig;
    const HttpBuffer* hb = GetHttpBuffer(HTTP_BUFFER_STAT_CODE);

    /*Not HTTP response, return*/
    if ( !hb )
        return 0;

    /*Not partial content, return*/
    if ( (hb->length != 3) || strncmp((const char*)hb->buf, "206", 3) )
        return 0;

    /*Use URI as the identifier for file*/
    if (GetHttpUriData(p->flow, &buf, &len, &type))
    {
        file_sig = str_to_hash(buf, len);
        file_resume_block_check(p, file_sig);
    }

    return 1;
}

static inline void _file_signature_lookup(FileContext* context,
        void* p, bool is_retransmit, bool suspend_block_verdict)
{
    File_Verdict verdict = FILE_VERDICT_UNKNOWN;
    Packet *pkt = (Packet *)p;

    if (!context->file_signature_enabled)
        return;

    if ((file_signature_done) && context->sha256 )
    {
        verdict = file_signature_done(p, pkt->flow, context->sha256, context->upload);
        file_stats.verdicts_signature[verdict]++;
    }

    if (suspend_block_verdict)
        context->suspend_block_verdict = true;

    context->verdict = verdict;

    if (verdict == FILE_VERDICT_LOG )
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__ALERT);
        pkt->packet_flags |= PKT_FILE_EVENT_SET;
    }
    else if (verdict == FILE_VERDICT_PENDING)
    {
        /*Can't decide verdict, drop packet and waiting...*/
        if (is_retransmit)
        {
            FileConfig *file_config =  (FileConfig *)context->file_config;
            /*Drop packets if not timeout*/
            if (pkt->pkth->ts.tv_sec <= context->expires)
            {
                Active_DropPacket();
                return;
            }
            /*Timeout, let packet go through OR block based on config*/
            context->file_signature_enabled = 0;
            if (file_config && file_config->block_timeout_lookup)
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                        FILE_SIGNATURE_SHA256_STR, RULE_TYPE__REJECT);
            else
                file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                        FILE_SIGNATURE_SHA256_STR, RULE_TYPE__ALERT);
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else
        {
            FileConfig *file_config =  (FileConfig *)context->file_config;
            if (file_config)
                context->expires = (time_t)(file_config->file_lookup_timeout + pkt->pkth->ts.tv_sec);
            Active_DropPacket();
	    stream.set_event_handler(pkt->flow, s_cb_id, SE_REXMIT);
            return;
        }
    }
    else if ((verdict == FILE_VERDICT_BLOCK) || (verdict == FILE_VERDICT_REJECT))
    {
        if (!context->suspend_block_verdict)
            render_block_verdict(context, p);

        return;
    }

    finish_signature_lookup(context, pkt->flow);
}

static inline void finish_signature_lookup(FileContext *context, Flow* flow)
{
    if (context->sha256)
    {
        context->file_signature_enabled = 0;
        file_stats.signatures_processed[context->file_type_id][context->upload]++;
        file_stats.signatures_processed_by_proto[stream.get_application_protocol_id(flow)]++;
    }
}

static File_Verdict get_file_verdict(Flow* flow)
{
    FileContext* context = get_file_context(flow);

    if (context == NULL)
        return FILE_VERDICT_UNKNOWN;

    return context->verdict;
}

static void render_block_verdict(void *ctx, void *p)
{
    FileContext *context = (FileContext*)ctx;
    Packet* pkt = (Packet*)p;

    if (p == NULL)
        return;

    if (context == NULL)
    {
        context = get_file_context(pkt->flow);

        if (context == NULL)
            return;
    }

    if (context->verdict == FILE_VERDICT_BLOCK)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__DROP);
        Active_ForceDropPacket();
        DisableInspection(pkt);
        pkt->packet_flags |= PKT_FILE_EVENT_SET;
        add_file_to_block(pkt, context->verdict, 0, context->sha256);
    }
    else if (context->verdict == FILE_VERDICT_REJECT)
    {
        file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                FILE_SIGNATURE_SHA256_STR, RULE_TYPE__REJECT);
        Active_ForceDropPacket();
        DisableInspection(pkt);
        pkt->packet_flags |= PKT_FILE_EVENT_SET;
        add_file_to_block(pkt, context->verdict, 0, context->sha256);
    }

    finish_signature_lookup(context, pkt->flow);
}

static void file_signature_lookup(void* p, bool is_retransmit)
{
    Packet *pkt = (Packet *)p;
    FileContext* context = get_file_context(pkt->flow);
    if (!context)
        return;
    _file_signature_lookup(context, p, is_retransmit, false);
}

static void file_signature_callback(Packet* p)
{
    FileContext* context = get_file_context(p->flow);

    if (!context)
        return;

    _file_signature_lookup(context, p, 1, false);
}

/*
 * Return:
 *    1: continue processing/log/block this file
 *    0: ignore this file
 */
static int file_process( void* p, uint8_t* file_data, int data_size,
        FilePosition position, bool upload, bool suspend_block_verdict)
{
    FileContext* context;
    Packet *pkt = (Packet *)p;
    /* if both disabled, return immediately*/
    if ((!file_type_id_enabled) && (!file_signature_enabled))
        return 0;
    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return 0;
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
    if (DEBUG_FILE & GetDebugLevel())
#endif
#if defined(DEBUG_MSGS) || defined (REG_TEST)
        DumpHex(stdout, file_data, data_size);
    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "stream pointer %p\n", pkt->flow ););
#endif

    context = get_file_context(p, position, upload);
    if(check_http_partial_content(pkt))
    {
        context->file_type_enabled = false;
        context->file_signature_enabled = false;
        return 0;
    }

    if ((!context->file_type_enabled) && (!context->file_signature_enabled))
        return 0;

    context->file_config = snort_conf->file_config;
    file_direction_set(context,upload);
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
            return 0;
        }

        if (context->file_type_id != SNORT_FILE_TYPE_CONTINUE)
        {
            if (file_type_done)
            {
                verdict = file_type_done(p, pkt->flow, context->file_type_id, upload);
                file_stats.verdicts_type[verdict]++;
            }
            context->file_type_enabled = false;
            file_stats.files_processed[context->file_type_id][upload]++;
            file_stats.files_processed_by_proto[stream.get_application_protocol_id(pkt->flow)]++;
        }

        if (verdict == FILE_VERDICT_LOG )
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_info_from_ID(context->file_config,context->file_type_id), RULE_TYPE__ALERT);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else if (verdict == FILE_VERDICT_BLOCK)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_info_from_ID(context->file_config,context->file_type_id), RULE_TYPE__DROP);
            Active_ForceDropPacket();
            DisableInspection(pkt);
            updateFileSize(context, data_size, position);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
            add_file_to_block(pkt, verdict, context->file_type_id, NULL);
            return 1;
        }
        else if (verdict == FILE_VERDICT_REJECT)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_info_from_ID(context->file_config,context->file_type_id), RULE_TYPE__REJECT);
            Active_ForceDropPacket();
            DisableInspection(pkt);
            updateFileSize(context, data_size, position);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
            add_file_to_block(pkt, verdict, context->file_type_id, NULL);
            return 1;
        }
        else if (verdict == FILE_VERDICT_STOP)
        {
            context->file_signature_enabled = false;

        }
    }
    /*file signature calculation*/
    if (context->file_signature_enabled)
    {
        file_signature_sha256(context, file_data, data_size, position);

#if defined(DEBUG_MSGS) || defined (REG_TEST)
        if (
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
                (DEBUG_FILE & GetDebugLevel()) &&
#endif
                (context->sha256) )
        {
            file_sha256_print(context->sha256);
        }
#endif
        _file_signature_lookup(context, p, false, suspend_block_verdict);

    }
    updateFileSize(context, data_size, position);
    return 1;
}

static void set_file_name (Flow* flow, uint8_t* file_name, uint32_t name_size)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context = get_file_context(flow);

    file_name_set(context, file_name, name_size);
#if defined(DEBUG_MSGS) || defined (REG_TEST)
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
    if (DEBUG_FILE & GetDebugLevel())
#endif
        printFileContext(context);
#endif
}

/* Return 1: file name available,
 *        0: file name is unavailable
 */
static int get_file_name (Flow* flow, uint8_t **file_name, uint32_t *name_size)
{
    FileContext* context = get_file_context(flow);
    return file_name_get(context, file_name, name_size);

}
static uint64_t  get_file_size(Flow* flow)
{
    FileContext* context = get_file_context(flow);
    return file_size_get(context);
}

static uint64_t  get_file_processed_size(Flow* flow)
{
    FileContext* context = get_file_context(flow);

    if (context)
        return (context->processed_bytes);
    else
        return 0;
}

static void set_file_direction(Flow* flow, bool upload)
{
    FileContext* context = get_file_context(flow);
    file_direction_set(context,upload);
}

static bool get_file_direction(Flow* flow)
{
    FileContext* context = get_file_context(flow);
    return file_direction_get(context);
}

static uint8_t *get_file_sig_sha256(Flow* flow)
{
    FileContext* context = get_file_context(flow);
    return file_sig_sha256_get(context);
}

static void set_file_policy_callback(Get_file_policy_func policy_func)
{
    get_file_policy = policy_func;
}

static void enable_file_type(File_type_done_func callback)
{
    file_type_done = callback;
    file_type_id_enabled = true;
    start_file_processing();
}

static void enable_file_signature(File_signature_done_func callback)
{
    file_signature_done = callback;

    if ( !file_signature_enabled )
    {
        file_signature_enabled = true;
        start_file_processing();
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
    int64_t file_depth = -1;

    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

    if (!file_config)
        return -1;

    if (file_type_id_enabled)
    {
        /*Unlimited file depth*/
        if (!file_config->file_type_depth)
            return 0;
        file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled )
    {
        /*Unlimited file depth*/
        if (!file_config->file_signature_depth)
            return 0;

        if (file_config->file_signature_depth > file_depth)
            file_depth = file_config->file_signature_depth;

    }

    return file_depth;
}

static void set_file_name_from_log(FILE_LogState *log_state, void* pv)
{
    Flow* ssn = (Flow*)pv; // FIXIT eliminate need for cast

    if ((log_state) && (log_state->file_logged > log_state->file_current))
    {
        set_file_name(ssn, log_state->filenames + log_state->file_current,
                log_state->file_logged -log_state->file_current);
    }
    else
    {
        set_file_name(ssn, NULL, 0);
    }
}

static uint32_t str_to_hash(uint8_t *str, int length )
{
    uint32_t a,b,c,tmp;
    int i,j,k,l;
    a = b = c = 0;
    for (i=0,j=0;i<length;i+=4)
    {
        tmp = 0;
        k = length - i;
        if (k > 4)
            k=4;

        for (l=0;l<k;l++)
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
    final(a,b,c);
    return c;
}

#if 0
static void print_file_stats(int exiting)
{
    int i;
    uint64_t processed_total[2];
    uint64_t verdicts_total;

    if(!file_stats.files_total)
        return;

    LogMessage("File type stats:\n");

    LogMessage("         Type              Download   Upload \n");

    processed_total[0] = 0;
    processed_total[1] = 0;
    for (i = 0; i < FILE_ID_MAX; i++)
    {
        char* type_name =  file_info_from_ID(snort_conf->file_config, i);
        if (type_name &&
                (file_stats.files_processed[i][0] || file_stats.files_processed[i][1] ))
        {
            LogMessage("%12s(%3d)          " FMTu64("-10") " " FMTu64("-10") " \n",
                    type_name, i,
                    file_stats.files_processed[i][0], file_stats.files_processed[i][1]);
            processed_total[0]+= file_stats.files_processed[i][0];
            processed_total[1]+= file_stats.files_processed[i][1];
        }
    }
    LogMessage("            Total          " FMTu64("-10")"  " FMTu64("-10") " \n",
            processed_total[0], processed_total[1]);

    LogMessage("\nFile signature stats:\n");

    LogMessage("         Type              Download   Upload \n");

    processed_total[0] = 0;
    processed_total[1] = 0;
    for (i = 0; i < FILE_ID_MAX; i++)
    {
        char* type_name =  file_info_from_ID(snort_conf->file_config, i);
        if (type_name &&
                (file_stats.signatures_processed[i][0] || file_stats.signatures_processed[i][1] ))
        {
            LogMessage("%12s(%3d)          " FMTu64("-10") " " FMTu64("-10") " \n",
                    type_name, i,
                    file_stats.signatures_processed[i][0], file_stats.signatures_processed[i][1]);
            processed_total[0]+= file_stats.signatures_processed[i][0];
            processed_total[1]+= file_stats.signatures_processed[i][1];
        }
    }
    LogMessage("            Total          " FMTu64("-10") " " FMTu64("-10") " \n",
            processed_total[0], processed_total[1]);

    LogMessage("\nFile type verdicts:\n");

    verdicts_total = 0;
    for (i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_stats.verdicts_type[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                    file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                    file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                    file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                    file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                    file_stats.verdicts_type[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                    file_stats.verdicts_type[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    LogMessage("\nFile signature verdicts:\n");

    verdicts_total = 0;
    for (i = 0; i < FILE_VERDICT_MAX; i++)
    {
        verdicts_total+=file_stats.verdicts_signature[i];
        switch (i)
        {
        case FILE_VERDICT_UNKNOWN:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "UNKNOWN",
                    file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_LOG:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "LOG",
                    file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_STOP:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "STOP",
                    file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_BLOCK:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "BLOCK",
                    file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_REJECT:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "REJECT",
                    file_stats.verdicts_signature[i]);
            break;
        case FILE_VERDICT_PENDING:
            LogMessage("   %12s:           " FMTu64("-10") " \n", "PENDING",
                    file_stats.verdicts_signature[i]);
            break;
        default:
            break;
        }
    }
    LogMessage("   %12s:           " FMTu64("-10") " \n", "Total",verdicts_total);

    if (IsAdaptiveConfigured())
    {
        LogMessage("\nFiles processed by protocol IDs:\n");
        for (i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_stats.files_processed_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64("-10") " \n", i ,file_stats.files_processed_by_proto[i]);
            }
        }
        LogMessage("\nFile signatures processed by protocol IDs:\n");
        for (i = 0; i < MAX_PROTOCOL_ORDINAL; i++)
        {
            if (file_stats.signatures_processed_by_proto[i])
            {
                LogMessage("   %12d:           " FMTu64("-10") " \n", i ,file_stats.signatures_processed_by_proto[i]);
            }
        }
    }

    LogMessage("\nTotal files processed:     " FMTu64("-10") " \n", file_stats.files_total);
}
#endif

