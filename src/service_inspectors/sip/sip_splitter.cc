//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// sip_splitter.cc author Hui Cao <huica@cisco.com>
// sip_splitter.cc author Pratik Shinde <pshinde2@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sip_splitter.h"

#include <ctype.h>
#include <string.h>

using namespace snort;

const char SipSplitter::content_len_key[] = "Content-Length";
const char SipSplitter::content_len_key_compact[] = "l";

SipSplitter::SipSplitter(bool c2s) : StreamSplitter(c2s)
{
    reset_states();
}

void SipSplitter::reset_states()
{
    paf_state = SIP_PAF_START_STATE;
    content_length = UNKNOWN_CONTENT_LENGTH;
    next_letter = nullptr;
    body_state = SIP_PAF_BODY_UNKNOWN;
}

bool SipSplitter::find_data_end_single_line(const uint8_t ch)
{
    if (ch == '\n')
    {
        paf_state = SIP_PAF_CONTENT_LEN_CMD;
        return true;
    }
    return false;
}

bool SipSplitter::find_body(const uint8_t ch)
{
    switch (body_state)
    {
    case SIP_PAF_BODY_UNKNOWN:
        if (ch == '\r')
            body_state = SIP_PAF_BODY_START_FIRST_CR;
        else if (ch == '\n')
            body_state = SIP_PAF_BODY_START_FIRST_LF;
        break;
    case SIP_PAF_BODY_START_FIRST_CR:
        if (ch == '\n')
            body_state = SIP_PAF_BODY_START_SECOND_CR;
        else if (ch != '\r')
            body_state = SIP_PAF_BODY_UNKNOWN;
        break;
    case SIP_PAF_BODY_START_FIRST_LF:
        if (ch == '\n')
            return true;
        else if (ch == '\r')
            body_state = SIP_PAF_BODY_START_FIRST_CR;
        else
            body_state = SIP_PAF_BODY_UNKNOWN;
        break;
    case SIP_PAF_BODY_START_SECOND_CR:
        if (ch == '\r')
            body_state = SIP_PAF_BODY_START_SECOND_LF;
        else if (ch == '\n')
            return true;
        else
            body_state = SIP_PAF_BODY_UNKNOWN;
        break;
    case SIP_PAF_BODY_START_SECOND_LF:
        if (ch == '\n')
            return true;
        else if (ch == '\r')
            body_state = SIP_PAF_BODY_START_FIRST_CR;
        else
            body_state = SIP_PAF_BODY_UNKNOWN;
        break;
    }

    return false;
}

SipPafDataLenStatus SipSplitter::get_length(const uint8_t c)
{
    if (isspace(c))
    {
        if (content_length != UNKNOWN_CONTENT_LENGTH)
            return SIP_PAF_LENGTH_DONE;
    }
    else if (isdigit(c))
    {
        if (content_length == UNKNOWN_CONTENT_LENGTH)
            content_length = 0;

        uint64_t tmp_len = (10 * (uint64_t)content_length) + (c - '0');
        if (tmp_len < UINT32_MAX)
            content_length = (uint32_t)tmp_len;
        else
        {
            content_length = 0;
            return SIP_PAF_LENGTH_INVALID;
        }
    }
    else
    {
        content_length = 0;
        return SIP_PAF_LENGTH_INVALID;
    }

    return SIP_PAF_LENGTH_CONTINUE;
}

void SipSplitter::process_command(const uint8_t ch)
{
    if (next_letter == nullptr)
    {
        if (isspace(ch))
            return;
        if (toupper(ch) == toupper(content_len_key[0]))
        {
            next_letter = &content_len_key[1];
            return ;
        }
        else
            next_letter = content_len_key_compact;
    }

    char val = *next_letter;

    if (val == '\0')
    {
        if (ch == ':')
            paf_state = SIP_PAF_CONTENT_LEN_CONVERT;
        else if (!isblank(ch))
        {
            reset_states();
            find_data_end_single_line(ch);
        }
    }
    else if (toupper(ch) == toupper(val))
        next_letter++;
    else
    {
        reset_states();
        find_data_end_single_line(ch);
    }
}

StreamSplitter::Status SipSplitter::scan(
    Flow *, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    for (uint32_t i = 0; i < len; i++)
    {
        uint8_t ch = data[i];
        const uint8_t *next;
        SipPafDataLenStatus status;

        switch (paf_state)
        {
        case SIP_PAF_START_STATE:
            next = (const uint8_t *) memchr(&data[i], '\n', (len - i));
            if (next)
            {
                i = (uint32_t)(next-data);
                paf_state = SIP_PAF_CONTENT_LEN_CMD;
            }
            else
                return StreamSplitter::SEARCH;
            break;
        case SIP_PAF_CONTENT_LEN_CMD:
            process_command(ch);
            break;
        case SIP_PAF_CONTENT_LEN_CONVERT:
            status = get_length(ch);
            if ( status == SIP_PAF_LENGTH_DONE)
            {
                paf_state = SIP_PAF_BODY_SEARCH;
                find_body(ch);
            }
            else if (status == SIP_PAF_LENGTH_INVALID)
            {
                reset_states();
                find_data_end_single_line(ch);
            }
            break;
        case SIP_PAF_BODY_SEARCH:
            if (!find_body(ch))
                break;
            paf_state = SIP_PAF_FLUSH_STATE;
            //fallthrough
        case SIP_PAF_FLUSH_STATE:
            if (content_length == 0)
            {
                *fp = i+1;
                reset_states();
                return StreamSplitter::FLUSH;
            }
            content_length--;
        }
    }

    return StreamSplitter::SEARCH;
}
