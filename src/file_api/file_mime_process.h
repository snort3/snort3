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

// file_mime_process.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_PROCESS_H
#define FILE_MIME_PROCESS_H

// Provides list of MIME processing functions. Encoded file data will be decoded
// and file name will be extracted from MIME header
// FIXIT-L This will be refactored soon

#include <pcre.h>
#include "file_api/file_api.h"
#include "file_api/file_mime_config.h"
#include "utils/sf_email_attach_decode.h"

#define MAX_FILE                             1024
#define MAX_EMAIL                            1024
#define BOUNDARY                             0

/* state flags */
#define MIME_FLAG_FOLDING                    0x00000001
#define MIME_FLAG_IN_CONTENT_TYPE            0x00000002
#define MIME_FLAG_GOT_BOUNDARY               0x00000004
#define MIME_FLAG_DATA_HEADER_CONT           0x00000008
#define MIME_FLAG_IN_CONT_TRANS_ENC          0x00000010
#define MIME_FLAG_EMAIL_ATTACH               0x00000020
#define MIME_FLAG_MULTIPLE_EMAIL_ATTACH      0x00000040
#define MIME_FLAG_MIME_END                   0x00000080
#define MIME_FLAG_IN_CONT_DISP               0x00000200
#define MIME_FLAG_IN_CONT_DISP_CONT          0x00000400

#define STATE_DATA_INIT    0
#define STATE_DATA_HEADER  1    /* Data header section of data state */
#define STATE_DATA_BODY    2    /* Data body section of data state */
#define STATE_MIME_HEADER  3    /* MIME header section within data section */
#define STATE_DATA_UNKNOWN 4

/* Maximum length of header chars before colon, based on Exim 4.32 exploit */
#define MAX_HEADER_NAME_LEN 64

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

struct MailLogConfig
{
    uint32_t memcap = DEFAULT_MIME_MEMCAP;;
    char log_mailfrom = 0;
    char log_rcptto = 0;
    char log_filename = 0;
    char log_email_hdrs = 0;
    uint32_t email_hdrs_log_depth = 0;
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

typedef struct _MimePcre
{
    pcre* re;
    pcre_extra* pe;
} MimePcre;

/* log flags */
#define MIME_FLAG_MAIL_FROM_PRESENT               0x00000001
#define MIME_FLAG_RCPT_TO_PRESENT                 0x00000002
#define MIME_FLAG_FILENAME_PRESENT                0x00000004
#define MIME_FLAG_EMAIL_HDRS_PRESENT              0x00000008


typedef int (*Handle_header_line_func)(void* conf, const uint8_t* ptr,
    const uint8_t* eol, int
    max_header_len, void* mime_ssn);
typedef int (*Normalize_data_func)(void* conf, const uint8_t* ptr,
    const uint8_t* data_end);
typedef void (*Decode_alert_func)(void* decode_state);
typedef void (*Reset_state_func)(void* ssn);
typedef bool (*Is_end_of_data_func)(void* ssn);

struct MimeMethods
{
    Handle_header_line_func handle_header_line;
    Normalize_data_func normalize_data;
    Decode_alert_func decode_alert;
    Reset_state_func reset_state;
    Is_end_of_data_func is_end_of_data;
};


struct MimeState
{
    int data_state;
    int state_flags;
    int log_flags;
    void* decode_state;
    MimeDataPafInfo mime_boundary;
    DecodeConfig* decode_conf;
    MailLogConfig* log_config;
    MAIL_LogState* log_state;
    void* config;
    MimeMethods* methods;
};

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


int log_file_name(const uint8_t* start, int length, FILE_LogState* log_state, bool* disp_cont);
int set_log_buffers(MAIL_LogState** log_state, MailLogConfig* conf);
void init_mime(void);
void free_mime(void);
const uint8_t* process_mime_data(Flow *flow, const uint8_t *start, const uint8_t *end,
                MimeState *mime_ssn, bool upload, FilePosition position);
void free_mime_session(MimeState*);
void free_mime_session(MimeState&);
void finalize_mime_position(Flow* flow, void* decode_state, FilePosition* position);
void reset_mime_paf_state(MimeDataPafInfo *data_info);
/*  Process data boundary and flush each file based on boundary*/
bool process_mime_paf_data(MimeDataPafInfo *data_info,  uint8_t val);
bool check_data_end(void *end_state,  uint8_t val);

#endif

