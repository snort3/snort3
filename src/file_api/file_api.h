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
#include "main/snort_types.h"

#define     ENABLE_FILE_TYPE_IDENTIFICATION      0x1
#define     ENABLE_FILE_SIGNATURE_SHA256         0x2
#define     FILE_ALL_ON                          0xFFFFFFFF
#define     FILE_ALL_OFF                         0x00000000
#define     MAX_FILE                             1024
#define     MAX_EMAIL                            1024

#define     FILE_RESUME_BLOCK                    0x01
#define     FILE_RESUME_LOG                      0x02

/* log flags */
#define MIME_FLAG_MAIL_FROM_PRESENT               0x00000001
#define MIME_FLAG_RCPT_TO_PRESENT                 0x00000002
#define MIME_FLAG_FILENAME_PRESENT                0x00000004
#define MIME_FLAG_EMAIL_HDRS_PRESENT              0x00000008


struct FILE_LogState
{
    uint8_t* filenames;
    uint16_t file_logged;
    uint16_t file_current;
};

struct MAIL_LogState
{
    unsigned char* emailHdrs;
    uint32_t log_depth;
    uint32_t hdrs_logged;
    uint8_t* recipients;
    uint16_t rcpts_logged;
    uint8_t* senders;
    uint16_t snds_logged;
    FILE_LogState file_log;
};

struct MAIL_LogConfig
{
    uint32_t memcap;
    char log_mailfrom;
    char log_rcptto;
    char log_filename;
    char log_email_hdrs;
    uint32_t email_hdrs_log_depth;
};

/* State tracker for data */
enum MimeDataState
{
    MIME_PAF_FINDING_BOUNDARY_STATE,
    MIME_PAF_FOUND_BOUNDARY_STATE
};

/* State tracker for Boundary Signature */
enum MimeBoundaryState
{
    MIME_PAF_BOUNDARY_UNKNOWN = 0,      /* UNKNOWN */
    MIME_PAF_BOUNDARY_LF,               /* '\n' */
    MIME_PAF_BOUNDARY_HYPEN_FIRST,      /* First '-' */
    MIME_PAF_BOUNDARY_HYPEN_SECOND      /* Second '-' */
};

/* State tracker for end of pop/smtp command */
enum DataEndState
{
    PAF_DATA_END_UNKNOWN,         /* Start or UNKNOWN */
    PAF_DATA_END_FIRST_CR,        /* First '\r' */
    PAF_DATA_END_FIRST_LF,        /* First '\n' */
    PAF_DATA_END_DOT,             /* '.' */
    PAF_DATA_END_SECOND_CR,       /* Second '\r' */
    PAF_DATA_END_SECOND_LF        /* Second '\n' */
};

#define MAX_MIME_BOUNDARY_LEN  70  /* Max length of boundary string, defined in RFC 2046 */

struct MimeDataPafInfo
{
    MimeDataState data_state;
    char boundary[ MAX_MIME_BOUNDARY_LEN + 1];            /* MIME boundary string + '\0' */
    int boundary_len;
    char* boundary_search;
    MimeBoundaryState boundary_state;
};

typedef int (* Handle_header_line_func)(void *conf, void* pkt, const uint8_t* ptr, const uint8_t* eol, int
    max_header_len, void* mime_ssn);
typedef int (* Normalize_data_func)(void *conf, void* pkt, const uint8_t* ptr, const uint8_t* data_end);
typedef void (* Decode_alert_func)(void* decode_state);
typedef void (* Reset_state_func)(void *ssn);
typedef bool (* Is_end_of_data_func)(void* ssn);

struct MimeMethods
{
    Handle_header_line_func handle_header_line;
    Normalize_data_func normalize_data;
    Decode_alert_func decode_alert;
    Reset_state_func reset_state;
    Is_end_of_data_func is_end_of_data;
};

struct DecodeConfig
{
    bool ignore_data;
    int max_mime_mem;
    int max_depth;
    int b64_depth;
    int qp_depth;
    int bitenc_depth;
    int uu_depth;
    int64_t file_depth;
};

struct MimeState
{
    int data_state;
    int state_flags;
    int log_flags;
    void* decode_state;
    MimeDataPafInfo mime_boundary;
    DecodeConfig* decode_conf;
    MAIL_LogConfig* log_config;
    MAIL_LogState* log_state;
    void *config;
    MimeMethods* methods;
};

#define FILE_API_VERSION5 2

typedef uint32_t (* Get_file_policy_func) (Flow* flow, int16_t app_id, bool upload);
typedef File_Verdict (* File_type_done_func) (void* p, Flow* flow, uint32_t file_type_id, bool
    upload);
typedef File_Verdict (* File_signature_done_func) (void* p, Flow* flow, uint8_t* file_sig, bool
    upload);
typedef void (* Log_file_action_func) (Flow* flow, int action);

typedef int (* File_process_func)(void* p, uint8_t* file_data, int data_size, FilePosition
    position,
    bool upload, bool suspend_block_verdict);
typedef int (* Get_file_name_func) (Flow* flow, uint8_t** file_name, uint32_t* name_len);
typedef uint64_t (* Get_file_size_func) (Flow* flow);
typedef bool (* Get_file_direction_func) (Flow* flow);
typedef uint8_t*(* Get_file_sig_sha256_func) (Flow* flow);

typedef void (* Set_file_name_func) (Flow* flow, uint8_t*, uint32_t);
typedef void (* Set_file_direction_func) (Flow* flow, bool);

typedef int64_t (* Get_file_depth_func) (void);

typedef void (* Set_file_policy_func)(Get_file_policy_func);
typedef void (* Enable_file_type_func)(File_type_done_func);
typedef void (* Enable_file_signature_func)(File_signature_done_func);
typedef void (* Set_file_action_log_func)(Log_file_action_func);

typedef int (* Log_file_name_func)(const uint8_t* start, int length, FILE_LogState* log_state,
    bool* disp_cont);
typedef void (* Set_file_name_from_log_func)(FILE_LogState* log_state, void* ssn);
typedef int (* Set_log_buffers_func)(MAIL_LogState** log_state, MAIL_LogConfig* conf);
typedef int (* File_resume_block_add_file_func)(void* pkt, uint32_t file_sig,
    uint32_t timeout, File_Verdict verdict, uint32_t file_type_id, uint8_t* signature);
typedef File_Verdict (* File_resume_block_check_func)(void* pkt, uint32_t file_sig);
typedef uint32_t (* Str_to_hash_func)(uint8_t* str, int length);
typedef void (* File_signature_lookup_func)(void* p, bool is_retransmit);
typedef void (* Set_mime_decode_config_defaults_func)(DecodeConfig* decode_conf);
typedef void (* Set_mime_log_config_defaults_func)(MAIL_LogConfig* log_config);
typedef int (* Parse_mime_decode_args_func)(DecodeConfig* decode_conf, char* arg, const
    char* preproc_name);
typedef void (* Check_decode_config_func)(DecodeConfig* decode_conf);
typedef const uint8_t* (* Process_mime_data_func)(void* packet, const uint8_t* start, const
    uint8_t* end,
    MimeState* mime_ssn, bool upload, bool paf_enabled);
typedef void (* Free_mime_session_func)(MimeState* mime_ssn);
typedef bool (* Is_decoding_enabled_func)(DecodeConfig* decode_conf);
typedef bool (* Is_decoding_conf_changed_func)(DecodeConfig* configNext, DecodeConfig* config,
    const char* preproc_name);
typedef bool (* Is_mime_log_enabled_func)(MAIL_LogConfig* log_config);
typedef void (* Finalize_mime_position_func)(Flow* flow, void* decode_state,
    FilePosition* position);
typedef File_Verdict (* Get_file_verdict_func)(Flow* flow);
typedef void (* Render_block_verdict_func)(void* ctx, void* p);
typedef bool (*Check_paf_abort_func)(void* ssn);
typedef FilePosition (*GetFilePosition)(void *pkt);
typedef void (*Reset_mime_paf_state_func)(MimeDataPafInfo *data_info);
/*  Process data boundary and flush each file based on boundary*/
typedef bool (*Process_mime_paf_data_func)(MimeDataPafInfo *data_info,  uint8_t data);
typedef bool (*Check_data_end_func)(void *end_state,  uint8_t data);

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
    File_resume_block_add_file_func file_resume_block_add_file;
    File_resume_block_check_func file_resume_block_check;
    Str_to_hash_func str_to_hash;
    File_signature_lookup_func file_signature_lookup;
    Set_mime_decode_config_defaults_func set_mime_decode_config_defauts;
    Set_mime_log_config_defaults_func set_mime_log_config_defauts;
    Parse_mime_decode_args_func parse_mime_decode_args;
    Check_decode_config_func check_decode_config;
    Process_mime_data_func process_mime_data;
    Free_mime_session_func free_mime_session;
    Is_decoding_enabled_func is_decoding_enabled;
    Is_decoding_conf_changed_func is_decoding_conf_changed;
    Is_mime_log_enabled_func is_mime_log_enabled;
    Finalize_mime_position_func finalize_mime_position;
    Reset_mime_paf_state_func reset_mime_paf_state;
    Process_mime_paf_data_func process_mime_paf_data;
    Check_data_end_func check_data_end;
    Check_paf_abort_func check_paf_abort;
    GetFilePosition get_file_position;

    Get_file_verdict_func get_file_verdict;
    Render_block_verdict_func render_block_verdict;
} FileAPI;

/* To be set by Stream */
SO_PUBLIC extern FileAPI* file_api;
extern File_type_done_func file_type_done;
extern File_signature_done_func file_signature_done;
extern Log_file_action_func log_file_action;

static inline void initFilePosition(FilePosition* position, uint64_t processed_size)
{
    *position = SNORT_FILE_START;
    if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}

static inline void updateFilePosition(FilePosition* position, uint64_t processed_size)
{
    if ((*position == SNORT_FILE_END) || (*position == SNORT_FILE_FULL))
        *position = SNORT_FILE_START;
    else if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}

static inline void finalFilePosition(FilePosition* position)
{
    if (*position == SNORT_FILE_START)
        *position = SNORT_FILE_FULL;
    else if (*position != SNORT_FILE_FULL)
        *position = SNORT_FILE_END;
}

static inline bool isFileStart(FilePosition position)
{
    return ((position == SNORT_FILE_START)|| (position == SNORT_FILE_FULL));
}

static inline bool isFileEnd(FilePosition position)
{
    return ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL));
}

static inline bool scanning_boundary(MimeDataPafInfo* mime_info, uint32_t boundary_start,
    uint32_t* fp)
{
    if (boundary_start &&
        mime_info->data_state == MIME_PAF_FOUND_BOUNDARY_STATE &&
        mime_info->boundary_state != MIME_PAF_BOUNDARY_UNKNOWN)
    {
        *fp = boundary_start;
        return true;
    }

    return false;
}

#endif /* FILE_API_H */

