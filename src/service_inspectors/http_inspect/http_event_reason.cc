//---------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
//---------------------------------------------------------------------------
// http_event_reason.cc Juan David Martin Castillo <jmartinc@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "http_event_reason.h"

const char* get_http_event_reason_msg(HttpEnums::GenericEventReasonCode event)
{
    switch (event)
    {
    case HttpEnums::BAD_REQUEST_TERMINATION:
        return "HTTP request bad termination";
    case HttpEnums::BAD_VERSION:
        return "HTTP version is bad";
    case HttpEnums::IMPROPER_WS:
        return "Improper whitespace in start line";
    case HttpEnums::INVALID_SUBVERSION:
        return "Invalid subversion";
    case HttpEnums::METHOD_NOT_PRESENT:
        return "HTTP method missing";
    case HttpEnums::METHOD_NOT_UPPERCASE:
        return "HTTP method not all upper case";
    case HttpEnums::NON_RFC_CHAR:
        return "Non-RFC character present";
    case HttpEnums::SIMPLE_REQUEST:
        return "Simple request (no version)";
    case HttpEnums::UNESCAPED_SPACE_URI:
        return "Unescaped space in URI";
    case HttpEnums::UNKNOWN_METHOD:
        return "Unknown method";
    case HttpEnums::URI_MISSING:
        return "URI missing";
    case HttpEnums::VERSION_HIGHER_THAN_1:
        return "Version higher than 1";
    case HttpEnums::VERSION_MALFORMED:
        return "HTTP version is malformed";
    case HttpEnums::VERSION_NOT_UPPERCASE:
        return "HTTP version not all upper case";
    default:
        return "Unknown reason";
    }
}

const char* get_detail_301_reason(HttpEnums::Detail301ReasonCode code)
{
    switch (code)
    {
    case HttpEnums::DETAIL_301_NONE:
        return "No detail available";
    case HttpEnums::DETAIL_301_CL_AND_TE_PRESENT:
        return "Content-Length and Transfer-Encoding are both present";
    case HttpEnums::DETAIL_301_HTTPX_HAS_TE:
        return "HTTP/2 or HTTP/3 has Transfer-Encoding";
    case HttpEnums::DETAIL_301_NEGATIVE_CL:
        return "Content-Length has a negative value";
    }

    assert(false);
    return "Unknown reason";
}
