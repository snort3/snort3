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
    if (uri_type != URI__NOTCOMPUTE)
    {
        return;
    }

    // Four basic types of HTTP URI
    // "*" means request does not apply to any specific resource
    if ((uri.length == 1) && (uri.start[0] == '*'))
    {
        uri_type = URI_ASTERISK;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
        abs_path.length = STAT_NOTPRESENT;
    }
    // CONNECT method uses an authority
    else if (method_id == METH_CONNECT)
    {
        uri_type = URI_AUTHORITY;
        scheme.length = STAT_NOTPRESENT;
        authority.length = uri.length;
        authority.start = uri.start;
        abs_path.length = STAT_NOTPRESENT;
    }
    // Absolute path is a path but no scheme or authority
    else if (uri.start[0] == '/')
    {
        uri_type = URI_ABSPATH;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
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

SchemeId NHttpUri::get_scheme_id()
{
    if (scheme_id != SCH__NOTCOMPUTE)
    {
        return scheme_id;
    }
    if (get_scheme().length <= 0)
    {
        scheme_id = SCH__NOSOURCE;
        return scheme_id;
    }

    // Normalize scheme name to lower case for matching purposes
    uint8_t* lower_scheme;
    if ((lower_scheme = scratch_pad.request(scheme.length)) == nullptr)
    {
        infractions += INF_NO_SCRATCH;
        scheme_id = SCH__INSUFMEMORY;
        return scheme_id;
    }
    norm_to_lower(scheme.start, scheme.length, lower_scheme, infractions, events, nullptr);
    scheme_id = (SchemeId)str_to_code(lower_scheme, scheme.length, scheme_list);
    return scheme_id;
}

const Field& NHttpUri::get_norm_host()
{
    if (host_norm.length != STAT_NOTCOMPUTE)
    {
        return host_norm;
    }
    if (get_host().length < 0)
    {
        host_norm.length = STAT_NOSOURCE;
        return host_norm;
    }
    UriNormalizer::normalize(host, host_norm, false, scratch_pad, infractions, events);
    return host_norm;
}

const Field& NHttpUri::get_norm_path()
{
    if (path_norm.length != STAT_NOTCOMPUTE)
    {
        return path_norm;
    }
    if (get_path().length < 0)
    {
        path_norm.length = STAT_NOSOURCE;
        return path_norm;
    }
    UriNormalizer::normalize(path, path_norm, true, scratch_pad, infractions, events);
    return path_norm;
}

const Field& NHttpUri::get_norm_query()
{
    if (query_norm.length != STAT_NOTCOMPUTE)
    {
        return query_norm;
    }
    if (get_query().length < 0)
    {
        query_norm.length = STAT_NOSOURCE;
        return query_norm;
    }
    UriNormalizer::normalize(query, query_norm, false, scratch_pad, infractions, events);
    return query_norm;
}

const Field& NHttpUri::get_norm_fragment()
{
    if (fragment_norm.length != STAT_NOTCOMPUTE)
    {
        return fragment_norm;
    }
    if (get_fragment().length < 0)
    {
        fragment_norm.length = STAT_NOSOURCE;
        return fragment_norm;
    }
    UriNormalizer::normalize(fragment, fragment_norm, false, scratch_pad, infractions, events);
    return fragment_norm;
}

int32_t NHttpUri::get_port_value()
{
    if (port_value != STAT_NOTCOMPUTE)
    {
        return port_value;
    }
    if (get_port().length <= 0)
    {
        port_value = STAT_NOSOURCE;
        return port_value;
    }
    port_value = 0;
    for (int k = 0; k < port.length; k++)
    {
        port_value = port_value * 10 + (port.start[k] - '0');
        if ((port.start[k] < '0') || (port.start[k] > '9') || (port_value > MAX_PORT_VALUE))
        {
            infractions += INF_BAD_PORT;
            events.create_event(EVENT_URI_BAD_PORT);
            port_value = STAT_PROBLEMATIC;
            break;
        }
    }
    return port_value;
}

void NHttpUri::parse_authority()
{
    if (host.length != STAT_NOTCOMPUTE)
    {
        return;
    }
    if (get_authority().length <= 0)
    {
        host.length = STAT_NOSOURCE;
        port.length = STAT_NOSOURCE;
        return;
    }
    host.start = authority.start;
    for (host.length = 0; (authority.start[host.length] != ':') && (host.length <
        authority.length); host.length++)
        ;
    if (host.length < authority.length)
    {
        port.length = authority.length - host.length - 1;
        port.start = authority.start + host.length + 1;
    }
    else
        port.length = STAT_NOTPRESENT;
}

void NHttpUri::parse_abs_path()
{
    if (path.length != STAT_NOTCOMPUTE)
        return;
    if (get_abs_path().length <= 0)
    {
        path.length = STAT_NOSOURCE;
        query.length = STAT_NOSOURCE;
        fragment.length = STAT_NOSOURCE;
        return;
    }
    path.start = abs_path.start;
    for (path.length = 0; (abs_path.start[path.length] != '?') && (abs_path.start[path.length] !=
        '#') && (path.length < abs_path.length); path.length++)
        ;
    if (path.length == abs_path.length)
    {
        query.length = STAT_NOTPRESENT;
        fragment.length = STAT_NOTPRESENT;
        return;
    }
    if (abs_path.start[path.length] == '?')
    {
        query.start = abs_path.start + path.length + 1;
        for (query.length = 0; (query.start[query.length] != '#') && (query.length <
            abs_path.length - path.length - 1); query.length++)
            ;
        fragment.start = query.start + query.length + 1;
        fragment.length = abs_path.length - path.length - 1 - query.length - 1;
    }
    else
    {
        query.length = STAT_NOTPRESENT;
        fragment.start = abs_path.start + path.length + 1;
        fragment.length = abs_path.length - path.length - 1;
    }
}

// Glue normalized URI fields back together
const Field& NHttpUri::get_norm_legacy()
{
    if (legacy_norm.length != STAT_NOTCOMPUTE)
    {
        return legacy_norm;
    }
    if (get_path().length >= 0)
    {
        UriNormalizer::normalize(path, path_norm, true, scratch_pad, infractions, events);
    }
    if (get_host().length >= 0)
    {
        UriNormalizer::normalize(host, host_norm, false, scratch_pad, infractions, events);
    }
    if (get_query().length >= 0)
    {
        UriNormalizer::normalize(query, query_norm, false, scratch_pad, infractions, events);
    }
    if (get_fragment().length >= 0)
    {
        UriNormalizer::normalize(fragment, fragment_norm, false, scratch_pad,
            infractions, events);
    }

    // We can reuse the raw URI for the normalized URI if no normalization is required
    if (!(infractions & INF_URI_NEED_NORM))
    {
        legacy_norm.start = uri.start;
        legacy_norm.length = uri.length;
        return legacy_norm;
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
        legacy_norm.start = scratch;
        legacy_norm.length = current - scratch;
    }
    else
        legacy_norm.length = STAT_INSUFMEMORY;
    return legacy_norm;
}

