//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#define XLINK_OTHER  1
#define XLINK_FIRST  2
#define XLINK_CHUNK  3

#define XLINK_LEN  12   /* strlen("X-LINK2STATE") */

/* X-Link2State overlong length */
#define XLINK2STATE_MAX_LEN  520

/* Prototypes */
static uint32_t get_xlink_hex_value(const uint8_t*, const uint8_t*);
static char get_xlink_keyword(const uint8_t*, const uint8_t*);

/*
 * Extract a number from a string
 *
 * @param   buf         pointer to beginning of buffer to parse
 * @param   end         end pointer of buffer to parse
 *
 * @return  unsigned long   value of number extracted
 *
 * @note    this could be more efficient, but the search buffer should be pretty short
 */
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

/*
 * Check for X-LINK2STATE keywords FIRST or CHUNK
 *
 *
 * @param   x           pointer to "X-LINK2STATE" in buffer
 * @param   x_len       length of buffer after x
 *
 * @retval  int         identifies which keyword found, if any
 */
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

    if (len > 5 && strncasecmp((const char*)ptr, "FIRST", 5) == 0)
    {
        return XLINK_FIRST;
    }
    else if (len > 5 && strncasecmp((const char*)ptr, "CHUNK", 5) == 0)
    {
        return XLINK_CHUNK;
    }

    return XLINK_OTHER;
}

/*
 * Handle X-Link2State vulnerability
 *
 *  From Lurene Grenier:

    The X-LINK2STATE command always takes the following form:

    X-LINK2STATE [FIRST|NEXT|LAST] CHUNK=<SOME DATA>

    The overwrite occurs when three criteria are met:

    No chunk identifier exists - ie neither FIRST, NEXT, or LAST are specified
    No previous FIRST chunk was sent
    <SOME DATA> has a length greater than 520 bytes

    Normally you send a FIRST chunk, then some intermediary chunks marked with
    either NEXT or not marked, then finally a LAST chunk.  If no first chunk is
    sent, and a chunk with no specifier is sent, it assumes it must append to
    something, but it has nothing to append to, so an overwrite occurs. Sending out
    of order chunks WITH specifiers results in an exception.

    So simply:

    if (gotFirstChunk)
        next; # chunks came with proper first chunk specified
    if (/X-LINK2STATE [FIRST|NEXT|LAST] CHUNK/)
    {
        if (/X-LINK2STATE FIRST CHUNK/) gotFirstChunk = TRUE;
        next; # some specifier is marked
    }
    if (chunkLen > 520)
       attempt = TRUE; # Gotcha!

    Usually it takes more than one unspecified packet in a row, but I think this is
    just a symptom of the fact that we're triggering a heap overwrite, and not a
    condition of the bug. However, if we're still getting FPs this might be an
    avenue to try.

 *
 * @param   p           standard Packet structure
 * @param   x           pointer to "X-LINK2STATE" in buffer
 *
 * @retval  1           if alert raised
 * @retval  0           if no alert raised
 */
int ParseXLink2State(SMTP_PROTO_CONF* config, snort::Packet* p, SMTPData* smtp_ssn, const uint8_t* ptr)
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
            snort::Active::reset_session(p);

        snort::DetectionEngine::queue_event(GID_SMTP, SMTP_XLINK2STATE_OVERFLOW);
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

