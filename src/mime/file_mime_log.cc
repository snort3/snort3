//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// file_mime_log.cc author Hui Cao <huica@cisco.com>
// 9.25.2012 - Initial Source Code. Hui Cao

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mime_log.h"

#include "file_api/file_flows.h"
#include "utils/safec.h"
#include "utils/util.h"

using namespace snort;

#define MAX_FILE                             1024
#define MAX_EMAIL                            1024

/* log flags */
#define MIME_FLAG_MAIL_FROM_PRESENT               0x00000001
#define MIME_FLAG_RCPT_TO_PRESENT                 0x00000002
#define MIME_FLAG_FILENAME_PRESENT                0x00000004
#define MIME_FLAG_EMAIL_HDRS_PRESENT              0x00000008

/* accumulate MIME attachment filenames. The filenames are appended by commas */
int MailLogState::log_file_name(const uint8_t* start, int length)
{
    if (!start || (length <= 0))
        return -1;

    uint8_t* alt_buf = filenames;
    int alt_size =  MAX_FILE;
    uint16_t* alt_len = &(file_logged);

    int sep = (*alt_len > 0) ? 1 : 0;
    int log_avail = alt_size - *alt_len - sep;

    if (!alt_buf || (log_avail <= 0))
        return -1;

    else if (log_avail < length )
        length = log_avail;

    if (length > 0)
    {
        if (sep)
        {
            alt_buf[*alt_len] = ',';
            *alt_len = *alt_len + 1;
        }
        memcpy_s(alt_buf + *alt_len, log_avail, start, length);
        file_current = *alt_len;
        *alt_len += length;
    }

    log_flags |= MIME_FLAG_FILENAME_PRESENT;

    return 0;
}

/* Accumulate EOL separated headers, one or more at a time */
int MailLogState::log_email_hdrs(const uint8_t* start, int length)
{
    if (length <= 0)
        return -1;

    int log_avail = log_depth - hdrs_logged;
    uint8_t* log_buf = (uint8_t*)emailHdrs;

    if (log_avail <= 0)
        return 0;

    if (length > log_avail)
        length = log_avail;

    /* appended by the EOL \r\n */

    if (length > log_avail)
        return -1;

    if (length > 0)
        memcpy_s(log_buf + hdrs_logged, log_avail, start, length);

    hdrs_logged += length;

    log_flags |= MIME_FLAG_EMAIL_HDRS_PRESENT;

    return 0;
}

/* Accumulate email addresses from RCPT TO and/or MAIL FROM commands. Email addresses are separated
   by comma */
int MailLogState::log_email_id(const uint8_t* start, int length, EmailUserType type)
{
    if (length <= 0)
        return -1;

    const uint8_t* tmp_eol = (const uint8_t*)memchr(start, ':', length);

    if ( !tmp_eol )
        return -1;

    if ((tmp_eol + 1) < (start + length))
    {
        length = length - ((tmp_eol + 1) - start);
        start = tmp_eol + 1;
    }
    else
        return -1;

    uint8_t* alt_buf;
    int alt_size;
    uint16_t* alt_len;

    switch (type)
    {
    case EMAIL_SENDER:
        alt_buf = senders;
        alt_size = MAX_EMAIL;
        alt_len = &(snds_logged);
        break;

    case EMAIL_RECIPIENT:
        alt_buf = recipients;
        alt_size = MAX_EMAIL;
        alt_len = &(rcpts_logged);
        break;

    default:
        return -1;
    }

    int sep = (*alt_len > 0) ? 1 : 0;
    int log_avail = alt_size - *alt_len - sep;

    if (log_avail <= 0 || !alt_buf)
        return -1;

    else if (log_avail < length )
        length = log_avail;

    if (length > 0)
    {
        if (sep)
        {
            alt_buf[*alt_len] = ',';
            *alt_len = *alt_len + 1;
        }
        memcpy_s(alt_buf + *alt_len, log_avail, start, length);
        *alt_len += length;
    }

    if (type == EMAIL_SENDER)
        log_flags |= MIME_FLAG_MAIL_FROM_PRESENT;
    else
        log_flags |= MIME_FLAG_RCPT_TO_PRESENT;

    return 0;
}

void MailLogState::get_file_name(uint8_t** buf, uint32_t* len)
{
    *buf = filenames;
    *len = file_logged;
}

void MailLogState::get_email_hdrs(uint8_t** buf, uint32_t* len)
{
    *buf = emailHdrs;
    *len = hdrs_logged;
}

void MailLogState::get_email_id(uint8_t** buf, uint32_t* len, EmailUserType type)
{
    if (type == EMAIL_SENDER)
    {
        *buf = senders;
        *len = snds_logged;
    }
    else
    {
        *buf = recipients;
        *len = rcpts_logged;
    }
}

bool MailLogState::is_file_name_present() const
{
    return log_flags & MIME_FLAG_FILENAME_PRESENT;
}

bool MailLogState::is_email_hdrs_present() const
{
    return log_flags & MIME_FLAG_EMAIL_HDRS_PRESENT;
}

bool MailLogState::is_email_from_present() const
{
    return log_flags & MIME_FLAG_MAIL_FROM_PRESENT;
}

bool MailLogState::is_email_to_present() const
{
    return log_flags & MIME_FLAG_RCPT_TO_PRESENT;
}

MailLogState::MailLogState(MailLogConfig* conf) : StashGenericObject(STASH_GENERIC_OBJECT_MIME)
{
    if (conf && (conf->log_email_hdrs || conf->log_filename
            || conf->log_mailfrom || conf->log_rcptto))
    {
        uint32_t bufsz = (2 * MAX_EMAIL) + MAX_FILE + conf->email_hdrs_log_depth;
        buf = (uint8_t*)snort_calloc(bufsz);

        log_depth = conf->email_hdrs_log_depth;
        recipients = buf;
        senders = buf + MAX_EMAIL;
        filenames = buf + (2 * MAX_EMAIL);
        emailHdrs = buf + (2 * MAX_EMAIL) + MAX_FILE;
    }

    rcpts_logged = 0;
    snds_logged = 0;
    file_logged = 0;
    file_current = 0;
    hdrs_logged = 0;
}

MailLogState::~MailLogState()
{
    if (buf != nullptr)
        snort_free(buf);
}

