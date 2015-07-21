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

// author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_LOG_H
#define FILE_MIME_LOG_H

// Provides list of MIME processing functions. Encoded file data will be decoded
// and file name will be extracted from MIME header

#include "file_api/file_api.h"
#include "file_api/file_mime_config.h"
#include "file_api/file_mime_log.h"

#define MAX_FILE                             1024
#define MAX_EMAIL                            1024

struct FileLogState
{
    uint8_t* filenames;
    uint16_t file_logged;
    uint16_t file_current;
};

class MailLogState
{
public:
    MailLogState(MailLogConfig* conf);
    ~MailLogState();
    /* accumulate MIME attachment filenames. The filenames are appended by commas */
    int log_file_name(const uint8_t* start, int length, bool* disp_cont);
    void set_file_name_from_log(void* pv);

private:
    int extract_file_name(const char** start, int length, bool* disp_cont);
    unsigned char* emailHdrs;
    uint32_t log_depth;
    uint32_t hdrs_logged;
    uint8_t* recipients;
    uint16_t rcpts_logged;
    uint8_t* senders;
    uint16_t snds_logged;
    FileLogState log_state;
    uint8_t* buf;
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

#endif

