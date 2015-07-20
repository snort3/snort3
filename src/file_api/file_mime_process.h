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

#include <pcre.h>
#include "file_api/file_api.h"
#include "file_api/file_mime_config.h"
#include "file_api/file_mime_paf.h"
#include "file_api/file_mime_log.h"
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

struct FileLogState
{
    uint8_t* filenames;
    uint16_t file_logged;
    uint16_t file_current;
};

struct MailLogState
{
    unsigned char* emailHdrs;
    uint32_t log_depth;
    uint32_t hdrs_logged;
    uint8_t* recipients;
    uint16_t rcpts_logged;
    uint8_t* senders;
    uint16_t snds_logged;
    FileLogState file_log;
};

struct MailLogConfig
{
    uint32_t memcap = DEFAULT_MIME_MEMCAP;
    char log_mailfrom = 0;
    char log_rcptto = 0;
    char log_filename = 0;
    char log_email_hdrs = 0;
    uint32_t email_hdrs_log_depth = 0;
};


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

class MimeSession
{
public:
    MimeSession(DecodeConfig*, MailLogConfig);
    ~MimeSession();
    static void init();
    static void close();
    const uint8_t* process_mime_data(Flow *flow, const uint8_t *start, const uint8_t *end,
        bool upload, FilePosition position);
private:
    int data_state = STATE_DATA_INIT;
    int state_flags = 0;
    int log_flags = 0;
    Email_DecodeState* decode_state;
    MimeDataPafInfo mime_boundary;
    DecodeConfig* decode_conf = NULL;
    MailLogConfig* log_config = NULL;
    MailLogState* log_state = NULL;
    void* config = NULL;
    MimeMethods* methods = NULL;
    int log_file_name(const uint8_t* start, int length, FileLogState* log_state, bool* disp_cont);
    void reset_mime_state();
    const uint8_t* process_mime_body(const uint8_t* ptr, const uint8_t* data_end,bool is_data_end);
    const uint8_t* process_mime_data_paf(Flow* flow, const uint8_t* start, const uint8_t* end,
        bool upload, FilePosition position);
};

#endif

