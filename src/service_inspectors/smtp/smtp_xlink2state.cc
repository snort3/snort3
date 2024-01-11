//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// smtp_xlink2state.c author Andy  Mullican
// This file handles the X-Link2State vulnerability.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp_xlink2state.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "packet_io/active.h"

#include "smtp_module.h"

using namespace snort;

#define XLINK_OTHER  1
#define XLINK_FIRST  2
#define XLINK_CHUNK  3

#define XLINK_LEN  12

#define XLINK2STATE_MAX_LEN  520

static uint32_t get_xlink_hex_value(const uint8_t*, const uint8_t*);
static char get_xlink_keyword(const uint8_t*, const uint8_t*);

static uint32_t get_xlink_hex_value(const uint8_t* buf, const uint8_t* end)
{
    uint32_t value = 0;

    if ((end - buf) < 8)
        return 0;

    const uint8_t* hex_end = buf + 8;

    while (buf < hex_end)
    {
        char c = toupper((int)*buf);

        /* Make sure it is a number or hex char; if not return with what we have */
        if (isdigit((int)c))
        {
            c = c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            c = (c - 'A') + 10;
        }
        else
        {
            return value;
        }

        value = (value * 16) + c;

        buf++;
    }

    return value;
}

static char get_xlink_keyword(const uint8_t* ptr, const uint8_t* end)
{
    int len;

    if (ptr == nullptr || end == nullptr)
        return XLINK_OTHER;

    ptr += XLINK_LEN;
    if (ptr >= end)
        return XLINK_OTHER;

    /* Skip over spaces */
    while (ptr < end && isspace((int)*ptr))
    {
        ptr++;
    }

    len = end - ptr;

    // cppcheck-suppress knownConditionTrueFalse
    if (len > 5)
    {
        if (strncasecmp((const char*)ptr, "FIRST", 5) == 0)
            return XLINK_FIRST;
        if (strncasecmp((const char*)ptr, "CHUNK", 5) == 0)
            return XLINK_CHUNK;
    }

    return XLINK_OTHER;
}

int ParseXLink2State(SmtpProtoConf* config, Packet* p, SMTPData* smtp_ssn, const uint8_t* ptr)
{
    const uint8_t* lf = nullptr;
    uint32_t len = 0;
    char x_keyword;
    const uint8_t* end;

    if (p == nullptr || ptr == nullptr)
        return 0;

    /* If we got a FIRST chunk on this stream, this is not an exploit */
    if (smtp_ssn->session_flags & SMTP_FLAG_XLINK2STATE_GOTFIRSTCHUNK)
        return 0;

    /* Calculate length from pointer to end of packet data */
    end = p->data + p->dsize;
    if (ptr >= end)
        return 0;

    /* Check for "FIRST" or "CHUNK" after X-LINK2STATE */
    x_keyword = get_xlink_keyword(ptr, end);
    if (x_keyword != XLINK_CHUNK)
    {
        if (x_keyword == XLINK_FIRST)
            smtp_ssn->session_flags |= SMTP_FLAG_XLINK2STATE_GOTFIRSTCHUNK;

        return 0;
    }

    ptr = (const uint8_t*)memchr((const char*)ptr, '=', end - ptr);
    if (ptr == nullptr)
        return 0;

    /* move past '=' and make sure we're within bounds */
    ptr++;
    if (ptr >= end)
        return 0;

    /*  Look for one of two patterns:
     *
     *  ... CHUNK={0000006d} MULTI (5) ({00000000051} ...
     *  ... CHUNK=AAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n
     */

    if (*ptr == '{')
    {
        /* move past '{' and make sure we're within bounds */
        ptr++;
        if ((ptr + 8) >= end)
            return 0;

        /* Get length - can we always trust it? */
        len = get_xlink_hex_value(ptr, end);
    }
    else
    {
        lf = (const uint8_t*)memchr((const char*)ptr, '\n', end - ptr);
        if (lf == nullptr)
            return 0;

        len = lf - ptr;
    }

    if (len > XLINK2STATE_MAX_LEN)
    {
        /* Need to drop the packet if we're told to
         * (outside of whether its thresholded). */
        if (config->xlink2state == DROP_XLINK2STATE)
            p->active->reset_session(p);

        DetectionEngine::queue_event(GID_SMTP, SMTP_XLINK2STATE_OVERFLOW);
        smtp_ssn->session_flags |= SMTP_FLAG_XLINK2STATE_ALERTED;

        return 1;
    }

    /* Check for more than one command in packet */
    ptr = (const uint8_t*)memchr((const char*)ptr, '\n', end - ptr);
    if (ptr == nullptr)
        return 0;

    /* move past '\n' */
    ptr++;

    if (ptr < end)
    {
        ParseXLink2State(config, p, smtp_ssn, ptr);
    }

    return 0;
}

