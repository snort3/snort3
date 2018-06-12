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
// http_uri.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_uri.h"

#include "hash/hashfcn.h"

using namespace HttpEnums;

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
    // Absolute path is a path but no scheme or authority
    else if (uri.start()[0] == '/')
    {
        uri_type = URI_ABSPATH;
        scheme.set(STAT_NOT_PRESENT);
        authority.set(STAT_NOT_PRESENT);
        abs_path.set(uri);
    }
    // Absolute URI includes scheme, authority, and path
    else
    {
        // Find the "://" and then the "/"
        int j;
        int k;
        for (j = 0; (j < uri.length()) && (uri.start()[j] != ':'); j++);
        for (k = j+3; (k < uri.length()) && (uri.start()[k] != '/'); k++);
        if ((k < uri.length()) && (uri.start()[j+1] == '/') && (uri.start()[j+2] == '/'))
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

void HttpUri::parse_authority()
{
    if (authority.length() <= 0)
    {
        host.set(STAT_NO_SOURCE);
        port.set(STAT_NO_SOURCE);
        return;
    }
    int32_t host_len;
    for (host_len = 0; (host_len < authority.length()) && (authority.start()[host_len] != ':');
        host_len++);
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

void HttpUri::check_oversize_dir(Field& uri_field)
{
    int32_t total_length = 0;
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
                total_length = cur - last_dir - 1;

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
    if ((host.length() > 0) &&
            UriNormalizer::need_norm(host, false, uri_param, infractions, events))
        *infractions += INF_URI_NEED_NORM_HOST;
    if ((path.length() > 0) &&
            UriNormalizer::need_norm(path, true, uri_param, infractions, events))
        *infractions += INF_URI_NEED_NORM_PATH;
    if ((query.length() > 0) &&
            UriNormalizer::need_norm(query, false, uri_param, infractions, events))
        *infractions += INF_URI_NEED_NORM_QUERY;
    if ((fragment.length() > 0) &&
            UriNormalizer::need_norm(fragment, false, uri_param, infractions, events))
        *infractions += INF_URI_NEED_NORM_FRAGMENT;

    if (!((*infractions & INF_URI_NEED_NORM_PATH)  || (*infractions & INF_URI_NEED_NORM_HOST) ||
          (*infractions & INF_URI_NEED_NORM_QUERY) || (*infractions & INF_URI_NEED_NORM_FRAGMENT)))
    {
        // This URI is OK, normalization not required
        host_norm.set(host);
        path_norm.set(path);
        query_norm.set(query);
        fragment_norm.set(fragment);
        classic_norm.set(uri);
        check_oversize_dir(path_norm);
        return;
    }

    HttpModule::increment_peg_counts(PEG_URI_NORM);

    // Create a new buffer containing the normalized URI by normalizing each individual piece.
    const uint32_t total_length = uri.length() + UriNormalizer::URI_NORM_EXPANSION;
    uint8_t* const new_buf = new uint8_t[total_length];
    uint8_t* current = new_buf;
    if (scheme.length() >= 0)
    {
        memcpy(current, scheme.start(), scheme.length());
        current += scheme.length();
        memcpy(current, "://", 3);
        current += 3;
    }
    if (host.length() > 0)
    {
        if (*infractions & INF_URI_NEED_NORM_HOST)
            UriNormalizer::normalize(host, host_norm, false, current, uri_param, infractions,
                events);
        else
        {
            // The host component is not changing but other parts of the URI are being normalized.
            // We need a copy of the raw host to provide that part of the normalized URI buffer we
            // are assembling. But the normalized component will refer to the original raw buffer
            // on the chance that the data retention policy in use might keep it longer.
            memcpy(current, host.start(), host.length());
            host_norm.set(host);
        }
        current += host_norm.length();
    }
    if (port.length() >= 0)
    {
        memcpy(current, ":", 1);
        current += 1;
        memcpy(current, port.start(), port.length());
        current += port.length();
    }
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
            UriNormalizer::normalize(fragment, fragment_norm, false, current, uri_param,
                infractions, events);
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

size_t HttpUri::get_file_proc_hash()
{
    if (abs_path_hash)
        return abs_path_hash;

    if (abs_path.length() > 0 )
    {
        abs_path_hash = snort::str_to_hash(abs_path.start(), abs_path.length());
    }

    return abs_path_hash;
}
