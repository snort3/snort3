//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// smtp_util.cc author Andy  Mullican
// This file contains SMTP helper functions.

#include "smtp_util.h"

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp.h"
#include "smtp_config.h"
#include "stream/stream_api.h"
#include "detection/detection_util.h"
#include "utils/safec.h"

static THREAD_LOCAL DataBuffer DecodeBuf;

void SMTP_GetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    /* XXX maybe should fatal error here since none of these
     * pointers should be NULL */
    if (ptr == NULL || end == NULL || eol == NULL || eolm == NULL)
        return;

    tmp_eol = (uint8_t*)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == NULL)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and
         * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}

void SMTP_ResetAltBuffer()
{
    DecodeBuf.len = 0;
}

const uint8_t* SMTP_GetAltBuffer(unsigned& len)
{
    len = DecodeBuf.len;
    return len ? DecodeBuf.data : nullptr;
}

int SMTP_CopyToAltBuffer(const uint8_t* start, int length)
{
    uint8_t* alt_buf;
    int alt_size;
    unsigned int* alt_len;

    /* if we make a call to this it means we want to use the alt buffer
     * regardless of whether we copy any data into it or not - barring a failure */
    smtp_normalizing = true;

    /* if start and end the same, nothing to copy */
    if (length == 0)
        return 0;

    alt_buf = DecodeBuf.data;
    alt_size = sizeof(DecodeBuf.data);
    alt_len = &DecodeBuf.len;

    if ((unsigned long)length > alt_size - *alt_len)
    {
        //SetDetectLimit(p, 0);
        smtp_normalizing = false;
        return -1;
    }

    memcpy_s(alt_buf + *alt_len, alt_size - *alt_len, start, length);
    *alt_len += length;

    return 0;
}

void SMTP_LogFuncs(SMTP_PROTO_CONF* config, Packet* p, MimeSession* mime_ssn)
{
    if (!mime_ssn)
        return;

    MailLogState* log = mime_ssn->get_log_state();

    if (!log || !config)
        return;

    if (log->is_file_name_present())
    {
        stream.set_extra_data(p->flow, p, config->xtra_filename_id);
    }

    if (log->is_email_from_present())
    {
        stream.set_extra_data(p->flow, p, config->xtra_mfrom_id);
    }

    if (log->is_email_to_present())
    {
        stream.set_extra_data(p->flow, p, config->xtra_rcptto_id);
    }

    if (log->is_email_hdrs_present())
    {
        stream.set_extra_data(p->flow, p, config->xtra_ehdrs_id);
    }
}

#ifdef DEBUG_MSGS
char smtp_print_buffer[65537];

const char* SMTP_PrintBuffer(Packet* p)
{
    const uint8_t* ptr = NULL;
    int len = 0;
    int iorig, inew;

    if (smtp_normalizing)
    {
        ptr = DecodeBuf.data;
        len = DecodeBuf.len;
    }
    else
    {
        ptr = p->data;
        len = p->dsize;
    }

    for (iorig = 0, inew = 0; iorig < len; iorig++, inew++)
    {
        if ((isascii((int)ptr[iorig]) && isprint((int)ptr[iorig])) || (ptr[iorig] == '\n'))
        {
            smtp_print_buffer[inew] = ptr[iorig];
        }
        else if (ptr[iorig] == '\r' &&
            ((iorig + 1) < len) && (ptr[iorig + 1] == '\n'))
        {
            iorig++;
            smtp_print_buffer[inew] = '\n';
        }
        else if (isspace((int)ptr[iorig]))
        {
            smtp_print_buffer[inew] = ' ';
        }
        else
        {
            smtp_print_buffer[inew] = '.';
        }
    }

    smtp_print_buffer[inew] = '\0';

    return &smtp_print_buffer[0];
}

#endif

