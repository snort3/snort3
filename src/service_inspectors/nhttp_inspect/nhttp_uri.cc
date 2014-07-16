/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      NHttpUri class
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_normalizers.h"
#include "nhttp_uri.h"

using namespace NHttpEnums;

void NHttpUri::parseUri() {
    if (uriType != URI__NOTCOMPUTE) return;
    if (uri.length <= 0) {
        uriType = URI__NOSOURCE;
        scheme.length = STAT_NOSOURCE;
        authority.length = STAT_NOSOURCE;
        absPath.length = STAT_NOSOURCE;
        return;
    }

    // Four basic types of HTTP URI
    // "*" means request does not apply to any specific resource
    if ((uri.length == 1) && (uri.start[0] == '*')) {
        uriType = URI_ASTERISK;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
        absPath.length = STAT_NOTPRESENT;
    }
    // CONNECT method uses an authority
    else if (methodId == METH_CONNECT) {
        uriType = URI_AUTHORITY;
        scheme.length = STAT_NOTPRESENT;
        authority.length = uri.length;
        authority.start = uri.start;
        absPath.length = STAT_NOTPRESENT;
    }
    // Absolute path is a path but no scheme or authority
    else if (uri.start[0] == '/') {
        uriType = URI_ABSPATH;
        scheme.length = STAT_NOTPRESENT;
        authority.length = STAT_NOTPRESENT;
        absPath.length = uri.length;
        absPath.start = uri.start;
    }
    // Absolute URI includes scheme, authority, and path
    else {
        // Find the "://" and then the "/"
        int j;
        int k;
        for (j = 0; (uri.start[j] != ':') && (j < uri.length); j++);
        for (k = j+3; (uri.start[k] != '/') && (k < uri.length); k++);
        if ((k < uri.length) && (uri.start[j+1] == '/') && (uri.start[j+2] == '/')) {
            uriType = URI_ABSOLUTE;
            scheme.length = j;
            scheme.start = uri.start;
            authority.length = k - j - 3;
            authority.start = uri.start + j + 3;
            absPath.length = uri.length - k;
            absPath.start = uri.start + k;
        }
        else {
            uriInfractions |= INF_BADURI;
            uriType = URI__PROBLEMATIC;
            scheme.length = STAT_PROBLEMATIC;
            authority.length = STAT_PROBLEMATIC;
            absPath.length = STAT_PROBLEMATIC;
        }
    }
}

SchemeId NHttpUri::getSchemeId() {
    if (schemeId != SCH__NOTCOMPUTE) return schemeId;
    if (getScheme().length <= 0) {
        schemeId = SCH__NOSOURCE;
        return schemeId;
    }

    // Normalize scheme name to lower case for matching purposes
    uint8_t *lowerScheme;
    if ((lowerScheme = scratchPad.request(scheme.length)) == nullptr) {
        uriInfractions |= INF_NOSCRATCH;
        schemeId = SCH__INSUFMEMORY;
        return schemeId;
    }
    norm2Lower(scheme.start, scheme.length, lowerScheme, uriInfractions, nullptr);
    schemeId = (SchemeId) strToCode(lowerScheme, scheme.length, schemeList);
    return schemeId;
}

field NHttpUri::getNormHost() {
    if (hostNorm.length != STAT_NOTCOMPUTE) return hostNorm;
    if (getHost().length < 0) {
        hostNorm.length = STAT_NOSOURCE;
        return hostNorm;
    }
    UriNormalizer::normalize(host, hostNorm, false, scratchPad, hostInfractions);
    return hostNorm;
}

field NHttpUri::getNormPath() {
    if (pathNorm.length != STAT_NOTCOMPUTE) return pathNorm;
    if (getPath().length < 0) {
        pathNorm.length = STAT_NOSOURCE;
        return pathNorm;
    }
    UriNormalizer::normalize(path, pathNorm, true, scratchPad, pathInfractions);
    return pathNorm;
}

field NHttpUri::getNormQuery() {
    if (queryNorm.length != STAT_NOTCOMPUTE) return queryNorm;
    if (getQuery().length < 0) {
        queryNorm.length = STAT_NOSOURCE;
        return queryNorm;
    }
    UriNormalizer::normalize(query, queryNorm, true, scratchPad, queryInfractions);
    return queryNorm;
}

field NHttpUri::getNormFragment() {
    if (fragmentNorm.length != STAT_NOTCOMPUTE) return fragmentNorm;
    if (getFragment().length < 0) {
        fragmentNorm.length = STAT_NOSOURCE;
        return fragmentNorm;
    }
    UriNormalizer::normalize(fragment, fragmentNorm, true, scratchPad, fragmentInfractions);
    return fragmentNorm;
}

int32_t NHttpUri::getPortValue() {
    if (portValue != STAT_NOTCOMPUTE) return portValue;
    if (getPort().length <= 0) {
        portValue = STAT_NOSOURCE;
        return portValue;
    }
    portValue = 0;
    for (int k = 0; k < port.length; k++) {
        portValue = portValue * 10 + (port.start[k] - '0');
        if ((port.start[k] < '0') || (port.start[k] > '9') || (portValue > 65535))
        {
            uriInfractions |= INF_BADPORT;
            portValue = STAT_PROBLEMATIC;
            break;
        }
    }
    return portValue;
}

void NHttpUri::parseAuthority() {
    if (host.length != STAT_NOTCOMPUTE) return;
    if (getAuthority().length <= 0) {
        host.length = STAT_NOSOURCE;
        port.length = STAT_NOSOURCE;
        return;
    }
    host.start = authority.start;
    for (host.length = 0; (authority.start[host.length] != ':') && (host.length < authority.length); host.length++);
    if (host.length < authority.length) {
        port.length = authority.length - host.length - 1;
        port.start = authority.start + host.length + 1;
    }
    else port.length = STAT_NOTPRESENT;
}

void NHttpUri::parseAbsPath() {
    if (path.length != STAT_NOTCOMPUTE) return;
    if (getAbsPath().length <= 0) {
        path.length = STAT_NOSOURCE;
        query.length = STAT_NOSOURCE;
        fragment.length = STAT_NOSOURCE;
        return;
    }
    path.start = absPath.start;
    for (path.length = 0; (absPath.start[path.length] != '?') && (absPath.start[path.length] != '#') && (path.length < absPath.length); path.length++);
    if (path.length == absPath.length) {
        query.length = STAT_NOTPRESENT;
        fragment.length = STAT_NOTPRESENT;
        return;
    }
    if (absPath.start[path.length] == '?') {
        query.start = absPath.start + path.length + 1;
        for (query.length = 0; (query.start[query.length] != '#') && (query.length < absPath.length - path.length - 1); query.length++);
        fragment.start = query.start + query.length + 1;
        fragment.length = absPath.length - path.length - 1 - query.length - 1;
    }
    else {
        query.length = STAT_NOTPRESENT;
        fragment.start = absPath.start + path.length + 1;
        fragment.length = absPath.length - path.length - 1;
    }
}

// Glue normalized URI fields back together 
field NHttpUri::getNormLegacy() {
    if (legacyNorm.length != STAT_NOTCOMPUTE) return legacyNorm;

    if (getPath().length >= 0) UriNormalizer::normalize(path, pathNorm, true, scratchPad, pathInfractions);
    if (getHost().length >= 0) UriNormalizer::normalize(host, hostNorm, false, scratchPad, hostInfractions);
    if (getQuery().length >= 0) UriNormalizer::normalize(query, queryNorm, false, scratchPad, queryInfractions);
    if (getFragment().length >= 0) UriNormalizer::normalize(fragment, fragmentNorm, false, scratchPad, fragmentInfractions);

    // We can reuse the raw URI for the normalized URI unless at least one part of the URI has been normalized
    if ((hostInfractions == 0) && (pathInfractions == 0) && (queryInfractions == 0) && (fragmentInfractions == 0)) {
        legacyNorm.start = uri.start;
        legacyNorm.length = uri.length;
        return legacyNorm;
    }

    // Glue normalized URI pieces back together
    const uint32_t totalLength = ((scheme.length >= 0) ? scheme.length + 3 : 0) +
                                 ((hostNorm.length >= 0) ? hostNorm.length : 0) +
                                 ((port.length >= 0) ? port.length + 1 : 0) +
                                 ((pathNorm.length >= 0) ? pathNorm.length : 0) +
                                 ((queryNorm.length >= 0) ? queryNorm.length + 1 : 0) +
                                 ((fragmentNorm.length >= 0) ? fragmentNorm.length + 1 : 0);
    uint8_t* const scratch = scratchPad.request(totalLength);
    if (scratch != nullptr) {
        uint8_t *current = scratch;
        if (scheme.length >= 0) {
            memcpy(current, scheme.start, scheme.length);
            current += scheme.length;
            memcpy(current, "://", 3);
            current += 3;
        }
        if (hostNorm.length >= 0) {
            memcpy(current, hostNorm.start, hostNorm.length);
            current += hostNorm.length;
        }
        if (port.length >= 0) {
            memcpy(current, ":", 1);
            current += 1;
            memcpy(current, port.start, port.length);
            current += port.length;
        }
        if (pathNorm.length >= 0) {
            memcpy(current, pathNorm.start, pathNorm.length);
            current += pathNorm.length;
        }
        if (queryNorm.length >= 0) {
            memcpy(current, "?", 1);
            current += 1;
            memcpy(current, queryNorm.start, queryNorm.length);
            current += queryNorm.length;
        }
        if (fragmentNorm.length >= 0) {
            memcpy(current, "#", 1);
            current += 1;
            memcpy(current, fragmentNorm.start, fragmentNorm.length);
            current += fragmentNorm.length;
        }
        assert(totalLength == current - scratch);
        scratchPad.commit(current - scratch);
        legacyNorm.start = scratch;
        legacyNorm.length = current - scratch;
    }
    else legacyNorm.length = STAT_INSUFMEMORY;
    return legacyNorm;
}


