//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_uri.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_uri.h"

#include "http_common.h"
#include "http_enum.h"
#include "hash/hash_key_operations.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

void HttpUri::parse_uri()
{
    // Four basic types of HTTP URI
    // "*" means request does not apply to any specific resource
    if ((uri.length() == 1) && (uri.start()[0] == '*'))
    {
        uri_type = URI_ASTERISK;
        scheme.set(STAT_NOT_PRESENT);
        authority.set(STAT_NOT_PRESENT);
        abs_path.set(STAT_NOT_PRESENT);
    }
    // CONNECT method uses an authority
    else if (method_id == METH_CONNECT)
    {
        uri_type = URI_AUTHORITY;
        scheme.set(STAT_NOT_PRESENT);
        authority.set(uri);
        abs_path.set(STAT_NOT_PRESENT);
    }
    // Origin form is a path but no scheme or authority
    else if (uri.start()[0] == '/')
    {
        uri_type = URI_ORIGIN;
        scheme.set(STAT_NOT_PRESENT);
        authority.set(STAT_NOT_PRESENT);
        abs_path.set(uri);
    }
    // Absolute URI includes scheme, authority, and path
    else
    {
        // <scheme>://<authority>/<path>
        // Find the "://" and then the "/"
        int j;
        int k;
        for (j = 0; (j < uri.length()) && (uri.start()[j] != ':') && scheme_char[uri.start()[j]];
            j++);
        for (k = j+3; (k < uri.length()) && (uri.start()[k] != '/'); k++);

        // Verify that 1) we found ://, 2) we found /, 3) scheme begins with a letter,
        // 4) scheme consists of legal characters (RFC 3986 3.1) and 5) scheme is no more than 36
        // characters in length
        if ((k < uri.length()) && (uri.start()[j] == ':') && (uri.start()[j+1] == '/') &&
            (uri.start()[j+2] == '/') && (uri.start()[0] >= 'A') && j <= MAX_SCHEME_LENGTH)
        {
            uri_type = URI_ABSOLUTE;
            scheme.set(j, uri.start());
            authority.set(k - j - 3, uri.start() + j + 3);
            abs_path.set(uri.length() - k, uri.start() + k);
        }
        else
        {
            *infractions += INF_BAD_URI;
            events->create_event(EVENT_URI_BAD_FORMAT);
            uri_type = URI__PROBLEMATIC;
            scheme.set(STAT_PROBLEMATIC);
            authority.set(STAT_PROBLEMATIC);
            abs_path.set(STAT_PROBLEMATIC);
        }
    }
}

int32_t HttpUri::find_host_len(const Field& authority)
{
    int32_t host_len = 0;
    // IPv6 addresses are surrounded by [] to protect embedded colons
    if (authority.start()[0] == '[')
    {
        for (; (host_len < authority.length()) && (authority.start()[host_len] != ']');
            host_len++);
    }

    for (; (host_len < authority.length()) && (authority.start()[host_len] != ':');
        host_len++);

    return host_len;
}

void HttpUri::parse_authority()
{
    if (authority.length() <= 0)
    {
        host.set(STAT_NO_SOURCE);
        port.set(STAT_NO_SOURCE);
        return;
    }

    int32_t host_len = find_host_len(authority);
    host.set(host_len, authority.start());
    if (host.length() < authority.length())
    {
        port.set(authority.length() - host.length() - 1, authority.start() + host.length() + 1);
    }
    else
        port.set(STAT_NOT_PRESENT);
}

void HttpUri::parse_abs_path()
{
    // path?query#fragment
    // path is always present in absolute path, while query and fragment are optional
    if (abs_path.length() <= 0)
    {
        path.set(STAT_NO_SOURCE);
        query.set(STAT_NO_SOURCE);
        fragment.set(STAT_NO_SOURCE);
        return;
    }
    int32_t path_len;
    for (path_len = 0; (path_len < abs_path.length()) && (abs_path.start()[path_len] != '?') &&
        (abs_path.start()[path_len] != '#'); path_len++);
    path.set(path_len, abs_path.start());
    if (path.length() == abs_path.length())
    {
        query.set(STAT_NOT_PRESENT);
        fragment.set(STAT_NOT_PRESENT);
        return;
    }
    if (abs_path.start()[path.length()] == '?')
    {
        int32_t query_len;
        const uint8_t* const query_start = abs_path.start() + path.length() + 1;
        for (query_len = 0; (query_len < abs_path.length() - path.length() - 1) &&
            (query_start[query_len] != '#'); query_len++);
        query.set(query_len, query_start);
        if (abs_path.length() - path.length() - 1 - query.length() == 0)
        {
            fragment.set(STAT_NOT_PRESENT);
            return;
        }
        fragment.set(abs_path.length() - path.length() - 1 - query.length() - 1,
                     query.start() + query.length() + 1);
    }
    else
    {
        query.set(STAT_NOT_PRESENT);
        fragment.set(abs_path.length() - path.length() - 1, abs_path.start() + path.length() + 1);
    }
}

void HttpUri::check_oversize_dir(const Field& uri_field)
{
    const uint8_t* last_dir = nullptr;
    const uint8_t* cur;
    const uint8_t* end;

    if ( uri_field.length() <= 0 )
        return;

    cur = uri_field.start();
    end = uri_field.start() + uri_field.length();

    while ( cur < end )
    {
        if ( *cur == '/' )
        {
            if ( last_dir )
            {
                int32_t total_length = cur - last_dir - 1;

                if ( total_length > uri_param.oversize_dir_length )
                {
                    *infractions += INF_OVERSIZE_DIR;
                    events->create_event(EVENT_OVERSIZE_DIR);
                    break;
                }
            }

            last_dir = cur;
        }
        cur++;
    }
}
void HttpUri::normalize()
{
    // Divide the URI up into its six components: scheme, host, port, path, query, and fragment
    parse_uri();
    parse_authority();
    parse_abs_path();

    // Almost all HTTP requests are honest and rarely need expensive normalization processing. We
    // do a quick scan for red flags and only perform normalization if something comes up.
    // Otherwise we set the normalized fields to point at the raw values.
    switch (uri_type)
    {
        case URI_ASTERISK:
        case URI__PROBLEMATIC:
            classic_norm.set(uri);
            return;
        case URI_AUTHORITY:
        {
            if ((host.length() > 0) &&
                UriNormalizer::need_norm(host, false, uri_param, infractions, events))
            {
                const int total_length = uri.length();

                uint8_t* const new_buf = new uint8_t[total_length];
                uint8_t* current = new_buf;

                *infractions += INF_URI_NEED_NORM_HOST;

                HttpModule::increment_peg_counts(PEG_URI_NORM);

                UriNormalizer::normalize(host, host_norm, false, current, uri_param, infractions,
                    events);

                current += host_norm.length();

                if (port.length() >= 0)
                {
                    memcpy(current, ":", 1);
                    current += 1;
                    memcpy(current, port.start(), port.length());
                    current += port.length();
                }

                assert(current - new_buf <= total_length);

                classic_norm.set(current - new_buf, new_buf, true);
                return;
            }

            classic_norm.set(uri);
            return;
        }
        case URI_ORIGIN:
        case URI_ABSOLUTE:
        {
            if ((path.length() > 0) &&
                    UriNormalizer::need_norm(path, true, uri_param, infractions, events))
                *infractions += INF_URI_NEED_NORM_PATH;
            if ((query.length() > 0) &&
                    UriNormalizer::need_norm(query, false, uri_param, infractions, events))
                *infractions += INF_URI_NEED_NORM_QUERY;

            if ((fragment.length() > 0) &&
                    UriNormalizer::need_norm(fragment, false, uri_param, infractions, events))
                *infractions += INF_URI_NEED_NORM_FRAGMENT;

            if (!((*infractions & INF_URI_NEED_NORM_PATH)
                  || (*infractions & INF_URI_NEED_NORM_QUERY)
                  || (*infractions & INF_URI_NEED_NORM_FRAGMENT)))
            {
                // This URI is OK, normalization not required
                path_norm.set(path);
                query_norm.set(query);
                fragment_norm.set(fragment);

                const int path_len = (path.length() > 0) ? path.length() : 0;
                // query_len = length of query + 1 (? char)
                const int query_len = (query.length() >= 0) ? query.length() + 1 : 0;
                // fragment_len = length of fragment + 1 (# char)
                const int fragment_len = (fragment.length() >= 0) ? fragment.length() + 1 : 0;

                classic_norm.set(path_len + query_len + fragment_len, abs_path.start());

                check_oversize_dir(path_norm);
                return;
            }

            HttpModule::increment_peg_counts(PEG_URI_NORM);

            // Create a new buffer containing the normalized URI by normalizing each individual piece.
            int total_length = path.length() ? path.length() + UriNormalizer::URI_NORM_EXPANSION : 0;
            total_length += (query.length() >= 0) ? query.length() + 1 : 0;
            total_length += (fragment.length() >= 0) ? fragment.length() + 1 : 0;
            uint8_t* const new_buf = new uint8_t[total_length];
            uint8_t* current = new_buf;

            if (path.length() > 0)
            {
                if (*infractions & INF_URI_NEED_NORM_PATH)
                    UriNormalizer::normalize(path, path_norm, true, current, uri_param, infractions,
                        events);
                else
                {
                    memcpy(current, path.start(), path.length());
                    path_norm.set(path);
                }
                current += path_norm.length();
            }
            if (query.length() >= 0)
            {
                memcpy(current, "?", 1);
                current += 1;
                if (*infractions & INF_URI_NEED_NORM_QUERY)
                    UriNormalizer::normalize(query, query_norm, false, current, uri_param, infractions,
                        events);
                else
                {
                    memcpy(current, query.start(), query.length());
                    query_norm.set(query);
                }
                current += query_norm.length();
            }
            if (fragment.length() >= 0)
            {
                memcpy(current, "#", 1);
                current += 1;
                if (*infractions & INF_URI_NEED_NORM_FRAGMENT)
                    UriNormalizer::normalize(fragment, fragment_norm, false, current, uri_param, infractions,
                        events);
                else
                {
                    memcpy(current, fragment.start(), fragment.length());
                    fragment_norm.set(fragment);
                }
                current += fragment_norm.length();
            }

            assert(current - new_buf <= total_length);

            if ((*infractions & INF_URI_MULTISLASH) || (*infractions & INF_URI_SLASH_DOT) ||
                (*infractions & INF_URI_SLASH_DOT_DOT))
            {
                HttpModule::increment_peg_counts(PEG_URI_PATH);
            }

            if ((*infractions & INF_URI_U_ENCODE) || (*infractions & INF_URI_UNKNOWN_PERCENT) ||
                (*infractions & INF_URI_PERCENT_UNRESERVED) || (*infractions & INF_URI_PERCENT_UTF8_2B) ||
                (*infractions & INF_URI_PERCENT_UTF8_3B) || (*infractions & INF_URI_DOUBLE_DECODE))
            {
                HttpModule::increment_peg_counts(PEG_URI_CODING);
            }

            check_oversize_dir(path_norm);

            classic_norm.set(current - new_buf, new_buf, true);
        }
        default:
            return;
    }
}

const Field& HttpUri::get_norm_scheme()
{
    if (scheme_norm.length() != STAT_NOT_COMPUTE)
        return scheme_norm;

    // Normalize upper case to lower case
    int k = 0;
    for (; (k < scheme.length()) && ((scheme.start()[k] < 'A') || (scheme.start()[k] > 'Z')); k++);

    if (k < scheme.length())
    {
        uint8_t* const buf = new uint8_t[scheme.length()];
        *infractions += INF_URI_NEED_NORM_SCHEME;
        for (int i=0; i < scheme.length(); i++)
        {
            buf[i] = scheme.start()[i] +
                (((scheme.start()[i] < 'A') || (scheme.start()[i] > 'Z')) ? 0 : 'a' - 'A');
        }
        scheme_norm.set(scheme.length(), buf, true);
    }
    else
        scheme_norm.set(scheme);

    return scheme_norm;
}

const Field& HttpUri::get_norm_host()
{
    if (host_norm.length() != STAT_NOT_COMPUTE)
        return host_norm;

    if (host.length() > 0 and
        UriNormalizer::need_norm(host, false, uri_param, infractions, events))
    {
        uint8_t *buf = new uint8_t[host.length()];

        *infractions += INF_URI_NEED_NORM_HOST;

        UriNormalizer::normalize(host, host_norm, false, buf, uri_param,
            infractions, events, true);
    }
    else
        host_norm.set(host);

    return host_norm;
}
