/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * ** Copyright (C) 2012-2013 Sourcefire, Inc.
 * ** AUTHOR: Hui Cao
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License Version 2 as
 * ** published by the Free Software Foundation.  You may not use, modify or
 * ** distribute this program under any other version of the GNU General
 * ** Public License.
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * */

/* file_api.h
 *
 * Purpose: Definition of the FileAPI.  To be used as a common interface
 *          for file process access for other preprocessors and detection plugins.
 *
 *  Author(s):  Hui Cao <hcao@sourcefire.com>
 *
 *  NOTES
 *  5.25.12 - Initial Source Code. Hcao
 */

#ifndef FILE_API_H
#define FILE_API_H

#include <sys/types.h>

#include "libs/file_lib.h"
#include "stream/stream_api.h"

#define     ENABLE_FILE_TYPE_IDENTIFICATION      0x1
#define     ENABLE_FILE_SIGNATURE_SHA256         0x2
#define     FILE_ALL_ON                          0xFFFFFFFF
#define     FILE_ALL_OFF                         0x00000000
#define     MAX_FILE                             1024
#define     MAX_EMAIL                            1024

#define     FILE_RESUME_BLOCK                    0x01
#define     FILE_RESUME_LOG                      0x02

typedef struct s_FILE_LogState
{
    uint8_t *filenames;
    uint16_t file_logged;
    uint16_t file_current;
} FILE_LogState;

typedef struct s_MAIL_LogState
{
    void *log_hdrs_bkt;
    unsigned char *emailHdrs;
    uint32_t log_depth;
    uint32_t hdrs_logged;
    uint8_t *recipients;
    uint16_t rcpts_logged;
    uint8_t *senders;
    uint16_t snds_logged;
    FILE_LogState file_log;
}MAIL_LogState;

typedef struct s_MAIL_LogConfig
{
    uint32_t  memcap;
    char  log_mailfrom;
    char  log_rcptto;
    char  log_filename;
    char  log_email_hdrs;
    uint32_t   email_hdrs_log_depth;
}MAIL_LogConfig;

#define MAX_MIME_BOUNDARY_LEN  70  /* Max length of boundary string, defined in RFC 2046 */

typedef struct _MimeBoundary
{
    char   boundary[2 + MAX_MIME_BOUNDARY_LEN + 1];  /* '--' + MIME boundary string + '\0' */
    int    boundary_len;
    void  *boundary_search;

} MimeBoundary;

typedef struct _DecodeConfig
{
    int  max_mime_mem;
    int max_depth;
    int b64_depth;
    int qp_depth;
    int bitenc_depth;
    int uu_depth;
    int64_t file_depth;
} DecodeConfig;

typedef struct _MimeState
{
    int data_state;
    int state_flags;
    int log_flags;
    void *decode_state;
    MimeBoundary  mime_boundary;
    DecodeConfig *decode_conf;
    MAIL_LogConfig *log_config;
    MAIL_LogState *log_state;
    void *decode_bkt;
    void *mime_mempool;
    void *log_mempool;
} MimeState;

#define FILE_API_VERSION5 2

typedef uint32_t (*Get_file_policy_func) (Flow* flow, int16_t app_id, bool upload);
typedef File_Verdict (*File_type_done_func) (void* p, Flow* flow, uint32_t file_type_id, bool upload);
typedef File_Verdict (*File_signature_done_func) (void* p, Flow* flow, uint8_t* file_sig, bool upload);
typedef void (*Log_file_action_func) (Flow* flow, int action);

typedef int (*File_process_func)( void* p, uint8_t* file_data, int data_size, FilePosition position,
        bool upload, bool suspend_block_verdict);
typedef int (*Get_file_name_func) (Flow* flow, uint8_t **file_name, uint32_t *name_len);
typedef uint64_t (*Get_file_size_func) (Flow* flow);
typedef bool (*Get_file_direction_func) (Flow* flow);
typedef uint8_t *(*Get_file_sig_sha256_func) (Flow* flow);

typedef void (*Set_file_name_func) (Flow* flow, uint8_t *, uint32_t);
typedef void (*Set_file_direction_func) (Flow* flow, bool);

typedef int64_t (*Get_file_depth_func) (void);

typedef void (*Set_file_policy_func)(Get_file_policy_func);
typedef void (*Enable_file_type_func)(File_type_done_func);
typedef void (*Enable_file_signature_func)(File_signature_done_func);
typedef void (*Set_file_action_log_func)(Log_file_action_func);

typedef int  (*Log_file_name_func)(const uint8_t *start, int length, FILE_LogState *log_state, bool *disp_cont);
typedef void (*Set_file_name_from_log_func)(FILE_LogState *log_state, void *ssn);
typedef int (*Set_log_buffers_func)(MAIL_LogState **log_state, MAIL_LogConfig *conf, void *mempool);
typedef void* (*Init_mime_mempool_func)(int max_mime_mem, int max_depth, void *mempool, const char *preproc_name);
typedef void* (*Init_log_mempool_func)(uint32_t email_hdrs_log_depth, uint32_t memcap,  void *mempool, const char *preproc_name);

typedef int (*File_resume_block_add_file_func)(void *pkt, uint32_t file_sig,
        uint32_t timeout, File_Verdict verdict, uint32_t file_type_id, uint8_t *signature);
typedef File_Verdict (*File_resume_block_check_func)(void *pkt, uint32_t file_sig);
typedef uint32_t (*Str_to_hash_func)(uint8_t *str, int length );
typedef void (*File_signature_lookup_func)(void* p, bool is_retransmit);
typedef void (*Set_mime_decode_config_defaults_func)(DecodeConfig *decode_conf);
typedef void (*Set_mime_log_config_defaults_func)(MAIL_LogConfig *log_config);
typedef int (*Parse_mime_decode_args_func)(DecodeConfig *decode_conf, char *arg, const char *preproc_name);
typedef const uint8_t * (*Process_mime_data_func)(void *packet, const uint8_t *start, const uint8_t *end,
        const uint8_t *data_end_marker, uint8_t *data_end, MimeState *mime_ssn, bool upload);
typedef void (*Free_mime_session_func)(MimeState *mime_ssn);
typedef bool (*Is_decoding_enabled_func)(DecodeConfig *decode_conf);
typedef bool (*Is_decoding_conf_changed_func)(DecodeConfig *configNext, DecodeConfig *config, const char *preproc_name);
typedef bool (*Is_mime_log_enabled_func)(MAIL_LogConfig *log_config);
typedef void (*Finalize_mime_position_func)(Flow *flow, void *decode_state, FilePosition *position);
typedef File_Verdict (*Get_file_verdict_func)(Flow* flow);
typedef void (*Render_block_verdict_func)(void *ctx, void *p);
typedef struct _file_api
{
    int version;

    /*File process function, called by preprocessors that provides file data*/
    File_process_func file_process;

    /*File properties*/
    Get_file_name_func get_file_name;
    Get_file_size_func get_file_size;
    Get_file_size_func get_file_processed_size;
    Get_file_direction_func get_file_direction;
    Get_file_sig_sha256_func get_sig_sha256;
    Set_file_name_func set_file_name;
    Set_file_direction_func set_file_direction;
    /*File call backs*/
    Set_file_policy_func set_file_policy_callback;
    Enable_file_type_func enable_file_type;
    Enable_file_signature_func enable_file_signature;
    Set_file_action_log_func set_file_action_log_callback;

    /*File configurations*/
    Get_file_depth_func get_max_file_depth;

    Log_file_name_func log_file_name;
    Set_file_name_from_log_func set_file_name_from_log;
    Set_log_buffers_func set_log_buffers;
    Init_mime_mempool_func init_mime_mempool;
    Init_log_mempool_func init_log_mempool;
    File_resume_block_add_file_func file_resume_block_add_file;
    File_resume_block_check_func file_resume_block_check;
    Str_to_hash_func str_to_hash;
    File_signature_lookup_func file_signature_lookup;
    Set_mime_decode_config_defaults_func set_mime_decode_config_defauts;
    Set_mime_log_config_defaults_func set_mime_log_config_defauts;
    Parse_mime_decode_args_func parse_mime_decode_args;
    Process_mime_data_func process_mime_data;
    Free_mime_session_func free_mime_session;
    Is_decoding_enabled_func is_decoding_enabled;
    Is_decoding_conf_changed_func is_decoding_conf_changed;
    Is_mime_log_enabled_func is_mime_log_enabled;
    Finalize_mime_position_func finalize_mime_position;

    Get_file_verdict_func get_file_verdict;
    Render_block_verdict_func render_block_verdict;
} FileAPI;

/* To be set by Stream5 */
extern FileAPI *file_api;
extern File_type_done_func file_type_done;
extern File_signature_done_func file_signature_done;
extern Log_file_action_func log_file_action;

static inline void initFilePosition(FilePosition *position, uint64_t processed_size)
{
    *position = SNORT_FILE_START;
    if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}
static inline void updateFilePosition(FilePosition *position, uint64_t processed_size)
{
    if ((*position == SNORT_FILE_END) || (*position == SNORT_FILE_FULL))
        *position = SNORT_FILE_START;
    else if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}
static inline void finalFilePosition(FilePosition *position)
{
    if (*position == SNORT_FILE_START)
        *position = SNORT_FILE_FULL;
    else if (*position != SNORT_FILE_FULL)
        *position = SNORT_FILE_END;
}

static inline bool isFileStart( FilePosition position)
{
   return ((position == SNORT_FILE_START)|| (position == SNORT_FILE_FULL));
}
#endif /* FILE_API_H */

