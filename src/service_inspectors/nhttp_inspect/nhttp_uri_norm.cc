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
#include <cstring>

#include "nhttp_enum.h"
#include "nhttp_uri_norm.h"

using namespace NHttpEnums;

void UriNormalizer::normalize(const Field& input, Field& result, bool do_path, uint8_t* buffer,
    const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions, NHttpEventGen& events)
{
    // Normalize percent encodings and similar escape sequences
    int32_t data_length = norm_char_clean(input, buffer, uri_param, infractions, events);

    detect_bad_char(Field(data_length, buffer), uri_param, infractions, events);

    norm_substitute(buffer, data_length, uri_param, infractions, events);

    // Normalize path directory traversals
    if (do_path && uri_param.simplify_path)
    {
        data_length = norm_path_clean(buffer, data_length, infractions, events);
    }

    result.set(data_length, buffer);
}

bool UriNormalizer::need_norm(const Field& uri_component, bool do_path,
    const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions, NHttpEventGen& events)
{
    bool need_it;
    if (do_path && uri_param.simplify_path)
        need_it = need_norm_path(uri_component, uri_param);
    else
        need_it = need_norm_no_path(uri_component, uri_param);

    if (!need_it)
    {
        // Since we are not going to normalize we need to check for bad characters now
        detect_bad_char(uri_component, uri_param, infractions, events);
    }

    return need_it;
}

bool UriNormalizer::need_norm_no_path(const Field& uri_component,
    const NHttpParaList::UriParam& uri_param)
{
    const int32_t& length = uri_component.length;
    const uint8_t* const & buf = uri_component.start;
    for (int32_t k = 0; k < length; k++)
    {
        if ((uri_param.uri_char[buf[k]] == CHAR_PERCENT) ||
            (uri_param.uri_char[buf[k]] == CHAR_SUBSTIT))
            return true;
    }
    return false;
}

bool UriNormalizer::need_norm_path(const Field& uri_component,
    const NHttpParaList::UriParam& uri_param)
{
    const int32_t& length = uri_component.length;
    const uint8_t* const & buf = uri_component.start;
    for (int32_t k = 0; k < length; k++)
    {
        switch (uri_param.uri_char[buf[k]])
        {
        case CHAR_NORMAL:
        case CHAR_EIGHTBIT:
            continue;
        case CHAR_PERCENT:
        case CHAR_SUBSTIT:
            return true;
        case CHAR_PATH:
            if (buf[k] == '/')
            {
                // slash is safe if not preceded by another slash
                if ((k == 0) || (buf[k-1] != '/'))
                    continue;
                return true;
            }
            else if (buf[k] == '.')
            {
                // period is safe if not preceded or followed by another path character
                if (((k == 0) || (uri_param.uri_char[buf[k-1]] != CHAR_PATH))          &&
                    ((k == length-1) || (uri_param.uri_char[buf[k+1]] != CHAR_PATH)))
                    continue;
                return true;
            }
            else
            {
                return true;
            }
        }
    }
    return false;
}

int32_t UriNormalizer::norm_char_clean(const Field& input, uint8_t* out_buf,
    const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions, NHttpEventGen& events)
{
    int32_t length = 0;
    for (int32_t k = 0; k < input.length; k++)
    {
        switch (uri_param.uri_char[input.start[k]])
        {
        case CHAR_NORMAL:
        case CHAR_PATH:
        case CHAR_EIGHTBIT:
        case CHAR_SUBSTIT:
            out_buf[length++] = input.start[k];
            break;
        case CHAR_PERCENT:
            if ((k+2 < input.length) && (as_hex[input.start[k+1]] != -1) &&
                (as_hex[input.start[k+2]] != -1))
            {
                // %hh => hex value
                out_buf[length++] = as_hex[input.start[k+1]] * 16 + as_hex[input.start[k+2]];
                k += 2;
            }
            else if ((k+1 < input.length) && (input.start[k+1] == '%'))
            {
                // %% => %
                out_buf[length++] = '%';
                k += 1;
            }
            else
            {
                // don't recognize, pass through for now (FIXIT-H unfinished feature)
                out_buf[length++] = '%';
            }

            // The result of percent decoding should not be an "unreserved" character. That's a
            // strong clue someone is hiding something.
            if (uri_param.unreserved_char[out_buf[length-1]])
            {
                infractions += INF_URI_PERCENT_UNRESERVED;
                events.create_event(EVENT_ASCII);
            }
            break;
        }
    }
    return length;
}

void UriNormalizer::detect_bad_char(const Field& uri_component,
    const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions, NHttpEventGen& events)
{
    // If the bad character detection feature is not configured we quit
    if (uri_param.bad_characters.count() == 0)
        return;

    for (int32_t k = 0; k < uri_component.length; k++)
    {
        if (uri_param.bad_characters[uri_component.start[k]])
        {
            infractions += INF_URI_BAD_CHAR;
            events.create_event(EVENT_NON_RFC_CHAR);
            return;
        }
    }
}

// Replace backslash with slash and plus with space
void UriNormalizer::norm_substitute(uint8_t* buf, int32_t length,
    const NHttpParaList::UriParam& uri_param, NHttpInfractions& infractions, NHttpEventGen& events)
{
    if (uri_param.backslash_to_slash)
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
    if (uri_param.plus_to_space)
    {
        for (int32_t k = 0; k < length; k++)
        {
            if (buf[k] == '+')
            {
                buf[k] = ' ';
            }
        }
    }
}

// Caution: worst case output length is one greater than input length
int32_t UriNormalizer::norm_path_clean(uint8_t* buf, const int32_t in_length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    // This is supposed to be the path portion of a URI. Read NHttpUri::parse_uri() for an
    // explanation.
    assert(buf[0] == '/');

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

// Provide traditional URI-style normalization for buffers that usually are not URIs
void UriNormalizer::classic_normalize(const Field& input, Field& result, uint8_t* buffer,
    const NHttpParaList::UriParam& uri_param)
{
    // The requirements for generating events related to these normalizations are unclear. It
    // definitely doesn't seem right to generate standard URI events. For now we won't generate
    // any events at all because these buffers may well not be URIs so regardless of what we find
    // it is "normal". Similarly we don't have any reason to track any infractions.

    // We want to reuse all the URI-normalization functions without complicating their event and
    // infraction logic with legacy problems. The following centralizes all the messiness here so
    // that we can conveniently modify it as requirements are better understood.

    NHttpInfractions unused;
    NHttpDummyEventGen dummy_ev;

    // Normalize character escape sequences
    int32_t data_length = norm_char_clean(input, buffer, uri_param, unused, dummy_ev);

    if (uri_param.simplify_path)
    {
        // Normalize path directory traversals
        // Find the leading slash if there is one
        uint8_t* first_slash = (uint8_t*)memchr(buffer, '/', data_length);
        if (first_slash != nullptr)
        {
            const int32_t uri_offset = first_slash - buffer;
            norm_substitute(buffer + uri_offset, data_length - uri_offset, uri_param, unused,
                dummy_ev);
            data_length = uri_offset +
                norm_path_clean(buffer + uri_offset, data_length - uri_offset, unused, dummy_ev);
        }
    }

    result.set(data_length, buffer);
}

bool UriNormalizer::classic_need_norm(const Field& uri_component, bool do_path,
    const NHttpParaList::UriParam& uri_param)
{
    NHttpInfractions unused;
    NHttpDummyEventGen dummy_ev;

    return need_norm(uri_component, do_path, uri_param, unused, dummy_ev);
}

