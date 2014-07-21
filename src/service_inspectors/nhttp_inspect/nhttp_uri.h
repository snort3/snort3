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
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpUri class
//-------------------------------------------------------------------------

class NHttpUri {
public:
    NHttpUri(const uint8_t* start, int32_t length, NHttpEnums::MethodId method) : uri(length, start), methodId(method),
       scratchPad(2*length+200) {};
    Field getUri() const { return uri; };
    NHttpEnums::UriType getUriType() { parseUri(); return uriType; };
    Field getScheme() { parseUri(); return scheme; };
    Field getAuthority() { parseUri(); return authority; };
    Field getHost() { parseAuthority(); return host; };
    Field getPort() { parseAuthority(); return port; };
    Field getAbsPath() { parseUri(); return absPath; };
    Field getPath() { parseAbsPath(); return path; };
    Field getQuery() { parseAbsPath(); return query; };
    Field getFragment() { parseAbsPath(); return fragment; };

    uint64_t getFormatInfractions() { parseUri(); return formatInfractions; };
    uint64_t getSchemeInfractions() { getSchemeId(); return schemeInfractions; };
    uint64_t getHostInfractions() { getNormHost(); return hostInfractions; };
    uint64_t getPortInfractions() { getPortValue(); return portInfractions; };
    uint64_t getPathInfractions() { getNormPath(); return pathInfractions; };
    uint64_t getQueryInfractions() { getNormQuery(); return queryInfractions; };
    uint64_t getFragmentInfractions() { getNormFragment(); return fragmentInfractions; };
    uint64_t getUriInfractions() { return getFormatInfractions() | getSchemeInfractions() | getHostInfractions() |
       getPortInfractions() | getPathInfractions() | getQueryInfractions() | getFragmentInfractions(); };

    NHttpEnums::SchemeId getSchemeId();
    Field getNormHost();
    int32_t getPortValue();
    Field getNormPath();
    Field getNormQuery();
    Field getNormFragment();
    Field getNormLegacy();

private:
    static const StrCode schemeList[];

    Field uri;
    const NHttpEnums::MethodId methodId;

    Field scheme;
    Field authority;
    Field host;
    Field port;
    Field absPath;
    Field path;
    Field query;
    Field fragment;

    uint64_t formatInfractions = 0;
    uint64_t schemeInfractions = 0;
    uint64_t hostInfractions = 0;
    uint64_t portInfractions = 0;
    uint64_t pathInfractions = 0;
    uint64_t queryInfractions = 0;
    uint64_t fragmentInfractions = 0;

    NHttpEnums::UriType uriType = NHttpEnums::URI__NOTCOMPUTE;
    NHttpEnums::SchemeId schemeId = NHttpEnums::SCH__NOTCOMPUTE;
    Field hostNorm;
    int32_t portValue = NHttpEnums::STAT_NOTCOMPUTE;
    Field pathNorm;
    Field queryNorm;
    Field fragmentNorm;
    Field legacyNorm;

    void parseUri();
    void parseAuthority();
    void parseAbsPath();

    ScratchPad scratchPad;
};

#endif





