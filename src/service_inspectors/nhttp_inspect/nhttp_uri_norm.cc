//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_uri_norm.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_uri_norm.h"

using namespace NHttpEnums;

void UriNormalizer::normalize(const Field& input, Field& result, bool do_path,
    ScratchPad& scratch_pad, NHttpInfractions& infractions, NHttpEventGen& events)
{
    if (result.length != STAT_NOTCOMPUTE)
        return;
    assert (input.length >= 0);

    // Almost all HTTP requests are honest and rarely need expensive normalization processing. We
    // do a quick scan for red flags and only perform normalization if something comes up.
    // Otherwise we set the normalized field to point at the raw value.
    if ( ( do_path && path_check(input.start, input.length, infractions, events))      ||
        (!do_path && no_path_check(input.start, input.length, infractions, events)))
    {
        result.start = input.start;
        result.length = input.length;
        return;
    }

    // Add an extra byte because normalization on rare occasions adds an extra character
    // We need working space for two copies to do multiple passes.
    // Round up to multiple of eight so that both copies are 64-bit aligned.
    const int32_t buffer_length = input.length + 1 + (8-(input.length+1)%8)%8;
    uint8_t* const scratch = scratch_pad.request(2 * buffer_length);
    if (scratch == nullptr)
    {
        result.length = STAT_INSUFMEMORY;
        return;
    }
    uint8_t* const front_half = scratch;
    uint8_t* const back_half = scratch + buffer_length;

    int32_t data_length;
    data_length = norm_char_clean(input.start, input.length, front_half, infractions, events,
        nullptr);
    if (do_path)
    {
        data_length = norm_backslash(front_half, data_length, back_half, infractions, events,
            nullptr);
        data_length = norm_path_clean(back_half, data_length, front_half, infractions, events,
            nullptr);
    }

    scratch_pad.commit(data_length);
    result.start = front_half;
    result.length = data_length;
}

bool UriNormalizer::no_path_check(const uint8_t* in_buf, int32_t in_length,
    NHttpInfractions& infractions, NHttpEventGen&)
{
    for (int32_t k = 0; k < in_length; k++)
    {
        if ((uri_char[in_buf[k]] == CHAR_NORMAL) || (uri_char[in_buf[k]] == CHAR_PATH))
            continue;
        infractions += INF_URI_NEED_NORM;
        return false;
    }
    return true;
}

bool UriNormalizer::path_check(const uint8_t* in_buf, int32_t in_length,
    NHttpInfractions& infractions, NHttpEventGen&)
{
    for (int32_t k = 0; k < in_length; k++)
    {
        if (uri_char[in_buf[k]] == CHAR_NORMAL)
            continue;
        if ((in_buf[k] == '/') && ((k == 0) || (in_buf[k-1] != '/')))
            continue;
        if (  (in_buf[k] == '.')                                               &&
              ((k == 0) || (uri_char[in_buf[k-1]] == CHAR_NORMAL))             &&
              ((k == in_length-1) || (uri_char[in_buf[k+1]] == CHAR_NORMAL)))
            continue;
        infractions += INF_URI_NEED_NORM;
        return false;
    }
    return true;
}

int32_t UriNormalizer::norm_char_clean(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions& infractions, NHttpEventGen& events, const void*)
{
    int32_t length = 0;
    for (int32_t k = 0; k < in_length; k++)
    {
        switch (uri_char[in_buf[k]])
        {
        case CHAR_NORMAL:
        case CHAR_PATH:
            out_buf[length++] = in_buf[k];
            break;
        case CHAR_INVALID:
            infractions += INF_URI_BAD_CHAR;
            events.create_event(EVENT_NON_RFC_CHAR);
            out_buf[length++] = in_buf[k];
            break;
        case CHAR_EIGHTBIT:
            infractions += INF_URI_8BIT_CHAR;
            events.create_event(EVENT_BARE_BYTE);
            out_buf[length++] = in_buf[k];
            break;
        case CHAR_PERCENT:
            if ((k+2 < in_length) && (as_hex[in_buf[k+1]] != -1) && (as_hex[in_buf[k+2]] != -1))
            {
                if (as_hex[in_buf[k+1]] <= 7)
                {
                    uint8_t value = as_hex[in_buf[k+1]] * 16 + as_hex[in_buf[k+2]];
                    if (good_percent[value])
                    {
                        // Normal % escape of an ASCII special character that is supposed to be
                        // escaped
                        infractions += INF_URI_PERCENT_NORMAL;
                        out_buf[length++] = '%';
                    }
                    else
                    {
                        // Suspicious % escape of an ASCII character that does not need to be
                        // escaped
                        infractions += INF_URI_PERCENT_ASCII;
                        events.create_event(EVENT_ASCII);
                        if (uri_char[value] == CHAR_INVALID)
                        {
                            infractions += INF_URI_BAD_CHAR;
                            events.create_event(EVENT_NON_RFC_CHAR);
                        }
                        out_buf[length++] = value;
                        k += 2;
                    }
                }
                else
                {
                    // UTF-8 decoding not implemented yet
                    infractions += INF_URI_PERCENT_UTF8;
                    events.create_event(EVENT_UTF_8);
                    out_buf[length++] = '%';
                }
            }
            else if ((k+5 < in_length) && (in_buf[k+1] == 'u') && (as_hex[in_buf[k+2]] != -1) &&
                (as_hex[in_buf[k+3]] != -1)
                && (as_hex[in_buf[k+4]] != -1) && (as_hex[in_buf[k+5]] != -1))
            {
                // 'u' UTF-16 decoding not implemented yet
                infractions += INF_URI_PERCENT_UCODE;
                events.create_event(EVENT_U_ENCODE);
                out_buf[length++] = '%';
            }
            else
            {
                // Don't recognize it
                infractions += INF_URI_PERCENT_OTHER;
                out_buf[length++] = '%';
            }
            break;
        }
    }
    return length;
}

// Convert URI backslashes to slashes
int32_t UriNormalizer::norm_backslash(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions& infractions, NHttpEventGen& events, const void*)
{
    for (int32_t k = 0; k < in_length; k++)
    {
        if (in_buf[k] != '\\')
            out_buf[k] = in_buf[k];
        else
        {
            out_buf[k] = '/';
            infractions += INF_URI_BACKSLASH;
            events.create_event(EVENT_IIS_BACKSLASH);
        }
    }
    return in_length;
}

// Caution: worst case output length is one greater than input length
int32_t UriNormalizer::norm_path_clean(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions& infractions, NHttpEventGen& events, const void*)
{
    int32_t length = 0;
    // It simplifies the code that handles /./ and /../ to pretend there is an extra '/' after the
    // buffer. Avoids making a special case of URIs that end in . or .. That is why the loop steps
    // off the end of the input buffer by saying <= instead of <.
    for (int32_t k = 0; k <= in_length; k++)
    {
        // Pass through all non-slash characters and also the leading slash
        if (((k < in_length) && (in_buf[k] != '/')) || (k == 0))
        {
            out_buf[length++] = in_buf[k];
        }
        // Ignore this slash if it directly follows another slash
        else if ((k < in_length) && (length >= 1) && (out_buf[length-1] == '/'))
        {
            infractions += INF_URI_MULTISLASH;
            events.create_event(EVENT_MULTI_SLASH);
        }
        // This slash is the end of a /./ pattern, ignore this slash and remove the period from the
        // output
        else if ((length >= 2) && (out_buf[length-1] == '.') && (out_buf[length-2] == '/'))
        {
            infractions += INF_URI_SLASH_DOT;
            events.create_event(EVENT_SELF_DIR_TRAV);
            length -= 1;
        }
        // This slash is the end of a /../ pattern, normalization depends on whether there is a
        // previous directory that we can remove
        else if ((length >= 3) && (out_buf[length-1] == '.') && (out_buf[length-2] == '.') &&
            (out_buf[length-3] == '/'))
        {
            infractions += INF_URI_SLASH_DOT_DOT;
            events.create_event(EVENT_DIR_TRAV);
            // Traversing above the root of the absolute path. A path of the form
            // /../../../foo/bar/whatever cannot be further normalized. Instead of taking away a
            // directory we leave the .. and write out the new slash. This code can write out the
            // pretend slash after the end of the buffer. That is intentional so that the normal
            // form of "/../../../.." is "/../../../../"
            if ( (length == 3) ||
                ((length >= 6) && (out_buf[length-4] == '.') && (out_buf[length-5] == '.') &&
                (out_buf[length-6] == '/')))
            {
                infractions += INF_URI_ROOT_TRAV;
                events.create_event(EVENT_WEBROOT_DIR);
                out_buf[length++] = '/';
            }
            // Remove the previous directory from the output. "/foo/bar/../" becomes "/foo/"
            else
            {
                for (length -= 3; out_buf[length-1] != '/'; length--)
                    ;
            }
        }
        // Pass through an ordinary slash
        else if (k < in_length)
        {
            out_buf[length++] = '/';
        }
    }
    return length;
}

