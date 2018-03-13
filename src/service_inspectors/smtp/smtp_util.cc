//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp_util.h"

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "protocols/packet.h"
#include "stream/stream.h"
#include "utils/safec.h"

#include "smtp.h"

using namespace snort;

void SMTP_GetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    /* XXX maybe should fatal error here since none of these
     * pointers should be NULL */
    if (ptr == nullptr || end == nullptr || eol == nullptr || eolm == nullptr)
        return;

    tmp_eol = (uint8_t*)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == nullptr)
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

void SMTP_ResetAltBuffer(Packet* p)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    buf.len = 0;
}

const uint8_t* SMTP_GetAltBuffer(Packet* p, unsigned& len)
{
    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    len = buf.len;
    return len ? buf.data : nullptr;
}

int SMTP_CopyToAltBuffer(Packet* p, const uint8_t* start, int length)
{
    /* if we make a call to this it means we want to use the alt buffer
     * regardless of whether we copy any data into it or not - barring a failure */
    smtp_normalizing = true;

    /* if start and end the same, nothing to copy */
    if (length == 0)
        return 0;

    DataBuffer& buf = DetectionEngine::get_alt_buffer(p);
    unsigned alt_size = sizeof(buf.data);

    if ((unsigned long)length > alt_size - buf.len)
    {
        smtp_normalizing = false;
        return -1;
    }

    memcpy_s(buf.data + buf.len, alt_size - buf.len, start, length);
    buf.len += length;

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
        Stream::set_extra_data(p->flow, p, config->xtra_filename_id);
    }

    if (log->is_email_from_present())
    {
        Stream::set_extra_data(p->flow, p, config->xtra_mfrom_id);
    }

    if (log->is_email_to_present())
    {
        Stream::set_extra_data(p->flow, p, config->xtra_rcptto_id);
    }

    if (log->is_email_hdrs_present())
    {
        Stream::set_extra_data(p->flow, p, config->xtra_ehdrs_id);
    }
}

