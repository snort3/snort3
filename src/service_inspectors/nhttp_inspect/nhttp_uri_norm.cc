//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

void UriNormalizer::normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    // Normalize character escape sequences
    int32_t data_length = norm_char_clean(input.start, input.length, buffer, infractions, events);

    // Normalize path directory traversals
    if (do_path)
    {
        norm_backslash(buffer, data_length, infractions, events);
        data_length = norm_path_clean(buffer, data_length, infractions, events);
    }

    result.set(data_length, buffer);
}

bool UriNormalizer::need_norm_no_path(const Field& uri_component)
{
    const int32_t& length = uri_component.length;
    const uint8_t* const & buf = uri_component.start;
    for (int32_t k = 0; k < length; k++)
    {
         if ((uri_char[buf[k]] == CHAR_NORMAL) || (uri_char[buf[k]] == CHAR_PATH))
            continue;
        return true;
    }
    return false;
}

bool UriNormalizer::need_norm_path(const Field& uri_component)
{
    const int32_t& length = uri_component.length;
    const uint8_t* const & buf = uri_component.start;
    for (int32_t k = 0; k < length; k++)
    {
        if (uri_char[buf[k]] == CHAR_NORMAL)
            continue;
        if ((buf[k] == '/') && ((k == 0) || (buf[k-1] != '/')))
            continue;
        if (  (buf[k] == '.')                                               &&
              ((k == 0) || (uri_char[buf[k-1]] == CHAR_NORMAL))             &&
              ((k == length-1) || (uri_char[buf[k+1]] == CHAR_NORMAL)))
            continue;
        return true;
    }
    return false;
}

int32_t UriNormalizer::norm_char_clean(const uint8_t* in_buf, int32_t in_length, uint8_t* out_buf,
    NHttpInfractions& infractions, NHttpEventGen& events)
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
void UriNormalizer::norm_backslash(uint8_t* buf, int32_t length, NHttpInfractions& infractions,
    NHttpEventGen& events)
{
    for (int32_t k = 0; k < length; k++)
    {
        if (buf[k] == '\\')
        {
            buf[k] = '/';
            infractions += INF_URI_BACKSLASH;
            events.create_event(EVENT_IIS_BACKSLASH);
        }
    }
}

// Caution: worst case output length is one greater than input length
int32_t UriNormalizer::norm_path_clean(uint8_t* buf, const int32_t in_length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    int32_t length = 0;
    // It simplifies the code that handles /./ and /../ to pretend there is an extra '/' after the
    // buffer. Avoids making a special case of URIs that end in . or .. That is why the loop steps
    // off the end of the input buffer by saying <= instead of <.
    for (int32_t k = 0; k <= in_length; k++)
    {
        // Pass through all non-slash characters and also the leading slash
        if (((k < in_length) && (buf[k] != '/')) || (k == 0))
        {
            buf[length++] = buf[k];
        }
        // Ignore this slash if it directly follows another slash
        else if ((k < in_length) && (length >= 1) && (buf[length-1] == '/'))
        {
            infractions += INF_URI_MULTISLASH;
            events.create_event(EVENT_MULTI_SLASH);
        }
        // This slash is the end of a /./ pattern, ignore this slash and remove the period from the
        // output
        else if ((length >= 2) && (buf[length-1] == '.') && (buf[length-2] == '/'))
        {
            infractions += INF_URI_SLASH_DOT;
            events.create_event(EVENT_SELF_DIR_TRAV);
            length -= 1;
        }
        // This slash is the end of a /../ pattern, normalization depends on whether there is a
        // previous directory that we can remove
        else if ((length >= 3) && (buf[length-1] == '.') && (buf[length-2] == '.') &&
            (buf[length-3] == '/'))
        {
            infractions += INF_URI_SLASH_DOT_DOT;
            events.create_event(EVENT_DIR_TRAV);
            // Traversing above the root of the absolute path. A path of the form
            // /../../../foo/bar/whatever cannot be further normalized. Instead of taking away a
            // directory we leave the .. and write out the new slash. This code can write out the
            // pretend slash after the end of the buffer. That is intentional so that the normal
            // form of "/../../../.." is "/../../../../"
            if ( (length == 3) ||
                ((length >= 6) && (buf[length-4] == '.') && (buf[length-5] == '.') &&
                (buf[length-6] == '/')))
            {
                infractions += INF_URI_ROOT_TRAV;
                events.create_event(EVENT_WEBROOT_DIR);
                buf[length++] = '/';
            }
            // Remove the previous directory from the output. "/foo/bar/../" becomes "/foo/"
            else
            {
                for (length -= 3; buf[length-1] != '/'; length--);
            }
        }
        // Pass through an ordinary slash
        else if (k < in_length)
        {
            buf[length++] = '/';
        }
    }
    return length;
}

