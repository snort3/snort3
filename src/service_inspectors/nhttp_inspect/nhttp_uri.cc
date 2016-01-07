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
// nhttp_uri.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
#include "nhttp_uri.h"

using namespace NHttpEnums;

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
        for (j = 0; (uri.start[j] != ':') && (j < uri.length); j++);
        for (k = j+3; (uri.start[k] != '/') && (k < uri.length); k++);
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
    for (host.length = 0; (authority.start[host.length] != ':') && (host.length <
        authority.length); host.length++);
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
    for (path.length = 0; (abs_path.start[path.length] != '?') && (abs_path.start[path.length] !=
        '#') && (path.length < abs_path.length); path.length++);
    if (path.length == abs_path.length)
    {
        query.length = STAT_NOT_PRESENT;
        fragment.length = STAT_NOT_PRESENT;
        return;
    }
    if (abs_path.start[path.length] == '?')
    {
        query.start = abs_path.start + path.length + 1;
        for (query.length = 0; (query.start[query.length] != '#') && (query.length <
            abs_path.length - path.length - 1); query.length++);
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
    // FIXIT-P generating the normalized URI components directly into the normalized classic buffer
    // would save a lot of memory and some copying.

    // Divide the URI up into its six components: scheme, host, port, path, query, and fragment
    parse_uri();
    parse_authority();
    parse_abs_path();

    // Normalize the individual components. We don't do anything with scheme or port.
    if (path.length >= 0)
    {
        UriNormalizer::normalize(path, path_norm, true, scratch_pad, infractions, events);
    }
    if (host.length >= 0)
    {
        UriNormalizer::normalize(host, host_norm, false, scratch_pad, infractions, events);
    }
    if (query.length >= 0)
    {
        UriNormalizer::normalize(query, query_norm, false, scratch_pad, infractions, events);
    }
    if (fragment.length >= 0)
    {
        UriNormalizer::normalize(fragment, fragment_norm, false, scratch_pad,
            infractions, events);
    }

    // We can reuse the raw URI for the normalized URI if no normalization is required
    if (!(infractions & INF_URI_NEED_NORM))
    {
        classic_norm.start = uri.start;
        classic_norm.length = uri.length;
        return;
    }

    // Glue normalized URI pieces back together
    const uint32_t total_length = ((scheme.length >= 0) ? scheme.length + 3 : 0) +
        ((host_norm.length >= 0) ? host_norm.length : 0) +
        ((port.length >= 0) ? port.length + 1 : 0) +
        ((path_norm.length >= 0) ? path_norm.length : 0) +
        ((query_norm.length >= 0) ? query_norm.length + 1 : 0) +
        ((fragment_norm.length >= 0) ? fragment_norm.length + 1 : 0);
    uint8_t* const scratch = scratch_pad.request(total_length);
    if (scratch != nullptr)
    {
        uint8_t* current = scratch;
        if (scheme.length >= 0)
        {
            memcpy(current, scheme.start, scheme.length);
            current += scheme.length;
            memcpy(current, "://", 3);
            current += 3;
        }
        if (host_norm.length >= 0)
        {
            memcpy(current, host_norm.start, host_norm.length);
            current += host_norm.length;
        }
        if (port.length >= 0)
        {
            memcpy(current, ":", 1);
            current += 1;
            memcpy(current, port.start, port.length);
            current += port.length;
        }
        if (path_norm.length >= 0)
        {
            memcpy(current, path_norm.start, path_norm.length);
            current += path_norm.length;
        }
        if (query_norm.length >= 0)
        {
            memcpy(current, "?", 1);
            current += 1;
            memcpy(current, query_norm.start, query_norm.length);
            current += query_norm.length;
        }
        if (fragment_norm.length >= 0)
        {
            memcpy(current, "#", 1);
            current += 1;
            memcpy(current, fragment_norm.start, fragment_norm.length);
            current += fragment_norm.length;
        }
        assert(total_length == current - scratch);
        scratch_pad.commit(current - scratch);
        classic_norm.start = scratch;
        classic_norm.length = current - scratch;
    }
    else
        classic_norm.length = STAT_INSUF_MEMORY;
}

