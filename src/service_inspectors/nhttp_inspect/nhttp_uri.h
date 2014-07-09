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
//  @brief      NHttpUri class declaration
//

#ifndef NHTTP_URI_H
#define NHTTP_URI_H

#include "nhttp_scratch_pad.h"
#include "nhttp_str_to_code.h"
#include "nhttp_uri_norm.h"

//-------------------------------------------------------------------------
// NHttpUri class
//-------------------------------------------------------------------------

class NHttpUri {
public:
    NHttpUri(const uint8_t* start, int32_t length, NHttpEnums::MethodId method) : methodId(method) {
       uri.length = length; uri.start = start; };

    field getUri() const { return uri; };
    NHttpEnums::UriType getUriType() { parseUri(); return uriType; };
    field getScheme() { parseUri(); return scheme; };
    field getAuthority() { parseUri(); return authority; };
    field getHost() { parseAuthority(); return host; };
    field getPort() { parseAuthority(); return port; };
    field getAbsPath() { parseUri(); return absPath; };
    field getPath() { parseAbsPath(); return path; };
    field getQuery() { parseAbsPath(); return query; };
    field getFragment() { parseAbsPath(); return fragment; };

    uint64_t getUriInfractions() const { return uriInfractions; };
    uint64_t getHostInfractions() const { return hostInfractions; };
    uint64_t getPathInfractions() const { return pathInfractions; };
    uint64_t getQueryInfractions() const { return queryInfractions; };
    uint64_t getFragmentInfractions() const { return fragmentInfractions; };

    NHttpEnums::SchemeId getSchemeId();
    field getNormHost();
    int32_t getPortValue();
    field getNormPath();
    field getNormQuery();
    field getNormFragment();
    field getNormLegacy();

private:
    static const StrCode schemeList[];

    field uri;
    const NHttpEnums::MethodId methodId;

    field scheme;
    field authority;
    field host;
    field port;
    field absPath;
    field path;
    field query;
    field fragment;

    uint64_t uriInfractions = 0;
    uint64_t hostInfractions = 0;
    uint64_t pathInfractions = 0;
    uint64_t queryInfractions = 0;
    uint64_t fragmentInfractions = 0;

    NHttpEnums::UriType uriType = NHttpEnums::URI__NOTCOMPUTE;
    NHttpEnums::SchemeId schemeId = NHttpEnums::SCH__NOTCOMPUTE;
    field hostNorm;
    int32_t portValue = NHttpEnums::STAT_NOTCOMPUTE;
    field pathNorm;
    field queryNorm;
    field fragmentNorm;
    field legacyNorm;

    void parseUri();
    void parseAuthority();
    void parseAbsPath();

    ScratchPad scratchPad {NHttpEnums::MAXOCTETS*2};
};

#endif





