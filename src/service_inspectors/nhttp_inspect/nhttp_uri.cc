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
// nhttp_uri.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_module.h"
#include "nhttp_uri.h"

using namespace NHttpEnums;

NHttpUri::~NHttpUri()
{
    if (classic_norm_allocated)
        delete[] classic_norm.start;
}

void NHttpUri::parse_uri()
{
    // Four basic types of HTTP URI
    // "*" means request does not apply to any specific resource
    if ((uri.length == 1) && (uri.start[0] == '*'))
    {
        uri_type = URI_ASTERISK;
        scheme.length = STAT_NOT_PRESENT;
        authority.length = STAT_NOT_PRESENT;
        abs_path.length = STAT_NOT_PRESENT;
    }
    // CONNECT method uses an authority
    else if (method_id == METH_CONNECT)
    {
        uri_type = URI_AUTHORITY;
        scheme.length = STAT_NOT_PRESENT;
        authority.length = uri.length;
        authority.start = uri.start;
        abs_path.length = STAT_NOT_PRESENT;
    }
    // Absolute path is a path but no scheme or authority
    else if (uri.start[0] == '/')
    {
        uri_type = URI_ABSPATH;
        scheme.length = STAT_NOT_PRESENT;
        authority.length = STAT_NOT_PRESENT;
        abs_path.length = uri.length;
        abs_path.start = uri.start;
    }
    // Absolute URI includes scheme, authority, and path
    else
    {
        // Find the "://" and then the "/"
        int j;
        int k;
        for (j = 0; (j < uri.length) && (uri.start[j] != ':'); j++);
        for (k = j+3; (k < uri.length) && (uri.start[k] != '/'); k++);
        if ((k < uri.length) && (uri.start[j+1] == '/') && (uri.start[j+2] == '/'))
        {
            uri_type = URI_ABSOLUTE;
            scheme.length = j;
            scheme.start = uri.start;
            authority.length = k - j - 3;
            authority.start = uri.start + j + 3;
            abs_path.length = uri.length - k;
            abs_path.start = uri.start + k;
        }
        else
        {
            infractions += INF_BAD_URI;
            events.create_event(EVENT_URI_BAD_FORMAT);
            uri_type = URI__PROBLEMATIC;
            scheme.length = STAT_PROBLEMATIC;
            authority.length = STAT_PROBLEMATIC;
            abs_path.length = STAT_PROBLEMATIC;
        }
    }
}

void NHttpUri::parse_authority()
{
    if (authority.length <= 0)
    {
        host.length = STAT_NO_SOURCE;
        port.length = STAT_NO_SOURCE;
        return;
    }
    host.start = authority.start;
    for (host.length = 0; (host.length < authority.length) &&
        (authority.start[host.length] != ':'); host.length++);
    if (host.length < authority.length)
    {
        port.length = authority.length - host.length - 1;
        port.start = authority.start + host.length + 1;
    }
    else
        port.length = STAT_NOT_PRESENT;
}

void NHttpUri::parse_abs_path()
{
    // path?query#fragment
    // path is always present in absolute path, while query and fragment are optional
    if (abs_path.length <= 0)
    {
        path.length = STAT_NO_SOURCE;
        query.length = STAT_NO_SOURCE;
        fragment.length = STAT_NO_SOURCE;
        return;
    }
    path.start = abs_path.start;
    for (path.length = 0; (path.length < abs_path.length) && (abs_path.start[path.length] != '?')
        && (abs_path.start[path.length] != '#'); path.length++);
    if (path.length == abs_path.length)
    {
        query.length = STAT_NOT_PRESENT;
        fragment.length = STAT_NOT_PRESENT;
        return;
    }
    if (abs_path.start[path.length] == '?')
    {
        query.start = abs_path.start + path.length + 1;
        for (query.length = 0; (query.length < abs_path.length - path.length - 1) &&
            (query.start[query.length] != '#'); query.length++);
        if (abs_path.length - path.length - 1 - query.length == 0)
        {
            fragment.length = STAT_NOT_PRESENT;
            return;
        }
        fragment.start = query.start + query.length + 1;
        fragment.length = abs_path.length - path.length - 1 - query.length - 1;
    }
    else
    {
        query.length = STAT_NOT_PRESENT;
        fragment.start = abs_path.start + path.length + 1;
        fragment.length = abs_path.length - path.length - 1;
    }
}

void NHttpUri::normalize()
{
    // Divide the URI up into its six components: scheme, host, port, path, query, and fragment
    parse_uri();
    parse_authority();
    parse_abs_path();

    // Almost all HTTP requests are honest and rarely need expensive normalization processing. We
    // do a quick scan for red flags and only perform normalization if something comes up.
    // Otherwise we set the normalized fields to point at the raw values.
    if ((host.length > 0) && UriNormalizer::need_norm(host, false, uri_param, infractions, events))
        infractions += INF_URI_NEED_NORM_HOST;
    if ((path.length > 0) && UriNormalizer::need_norm(path, true, uri_param, infractions, events))
        infractions += INF_URI_NEED_NORM_PATH;
    if ((query.length > 0) && UriNormalizer::need_norm(query, false, uri_param, infractions,
            events))
        infractions += INF_URI_NEED_NORM_QUERY;
    if ((fragment.length > 0) && UriNormalizer::need_norm(fragment, false, uri_param, infractions,
            events))
        infractions += INF_URI_NEED_NORM_FRAGMENT;

    if (!((infractions & INF_URI_NEED_NORM_PATH)  || (infractions & INF_URI_NEED_NORM_HOST) ||
          (infractions & INF_URI_NEED_NORM_QUERY) || (infractions & INF_URI_NEED_NORM_FRAGMENT)))
    {
        // This URI is OK, normalization not required
        host_norm = host;
        path_norm = path;
        query_norm = query;
        fragment_norm = fragment;
        classic_norm = uri;
        return;
    }

    NHttpModule::increment_peg_counts(PEG_URI_NORM);

    // Create a new buffer containing the normalized URI by normalizing each individual piece.
    const uint32_t total_length = uri.length + UriNormalizer::URI_NORM_EXPANSION;
    uint8_t* const new_buf = new uint8_t[total_length];
    uint8_t* current = new_buf;
    if (scheme.length >= 0)
    {
        memcpy(current, scheme.start, scheme.length);
        current += scheme.length;
        memcpy(current, "://", 3);
        current += 3;
    }
    if (host.length > 0)
    {
        if (infractions & INF_URI_NEED_NORM_HOST)
            UriNormalizer::normalize(host, host_norm, false, current, uri_param, infractions,
                events);
        else
        {
            // The host component is not changing but other parts of the URI are being normalized.
            // We need a copy of the raw host to provide that part of the normalized URI buffer we
            // are assembling. But the normalized component will refer to the original raw buffer
            // on the chance that the data retention policy in use might keep it longer.
            memcpy(current, host.start, host.length);
            host_norm = host;
        }
        current += host_norm.length;
    }
    if (port.length >= 0)
    {
        memcpy(current, ":", 1);
        current += 1;
        memcpy(current, port.start, port.length);
        current += port.length;
    }
    if (path.length > 0)
    {
        if (infractions & INF_URI_NEED_NORM_PATH)
            UriNormalizer::normalize(path, path_norm, true, current, uri_param, infractions,
                events);
        else
        {
            memcpy(current, path.start, path.length);
            path_norm = path;
        }
        current += path_norm.length;
    }
    if (query.length >= 0)
    {
        memcpy(current, "?", 1);
        current += 1;
        if (infractions & INF_URI_NEED_NORM_QUERY)
            UriNormalizer::normalize(query, query_norm, false, current, uri_param, infractions,
                events);
        else
        {
            memcpy(current, query.start, query.length);
            query_norm = query;
        }
        current += query_norm.length;
    }
    if (fragment.length >= 0)
    {
        memcpy(current, "#", 1);
        current += 1;
        if (infractions & INF_URI_NEED_NORM_FRAGMENT)
            UriNormalizer::normalize(fragment, fragment_norm, false, current, uri_param,
                infractions, events);
        else
        {
            memcpy(current, fragment.start, fragment.length);
            fragment_norm = fragment;
        }
        current += fragment_norm.length;
    }
    assert(current - new_buf <= total_length);

    if ((infractions & INF_URI_MULTISLASH) || (infractions & INF_URI_SLASH_DOT) ||
        (infractions & INF_URI_SLASH_DOT_DOT))
    {
        NHttpModule::increment_peg_counts(PEG_URI_PATH);
    }

    if ((infractions & INF_URI_U_ENCODE) || (infractions & INF_URI_UNKNOWN_PERCENT) ||
        (infractions & INF_URI_PERCENT_UNRESERVED) || (infractions & INF_URI_PERCENT_UTF8_2B) ||
        (infractions & INF_URI_PERCENT_UTF8_3B) || (infractions & INF_URI_DOUBLE_DECODE))
    {
        NHttpModule::increment_peg_counts(PEG_URI_CODING);
    }

    classic_norm.set(current - new_buf, new_buf);
    classic_norm_allocated = true;
}

