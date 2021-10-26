//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// appid_session.h author Sourcefire Inc.

#ifndef APPID_TYPES_H
#define APPID_TYPES_H
#include <cstdint>
// These values are used in Lua code as raw numbers. Do NOT reassign new values.
// 0 - 8 (inclusive)       : used heavily in CHP code. DO NOT CHANGE.
// 9 - NUM_METADATA_FIELDS : extra metadata buffers, beyond CHP.
// NUM_METADATA_FIELDS     : must always follow the last metadata FID.
// NUM_HTTP_FIELDS         : number of CHP fields, so always RSP_BODY_FID + 1
enum HttpFieldIds : uint8_t
{
    // 0-8: CHP fields. DO NOT CHANGE

    // Request-side headers
    REQ_AGENT_FID,          // 0
    REQ_HOST_FID,           // 1
    REQ_REFERER_FID,        // 2
    REQ_URI_FID,            // 3
    REQ_COOKIE_FID,         // 4
    REQ_BODY_FID,           // 5
    // Response-side headers
    RSP_CONTENT_TYPE_FID,   // 6
    RSP_LOCATION_FID,       // 7
    RSP_BODY_FID,           // 8

    // extra (non-CHP) metadata fields.
    MISC_VIA_FID,           // 9
    MISC_RESP_CODE_FID,     // 10
    MISC_SERVER_FID,        // 11
    MISC_XWW_FID,           // 12
    MISC_URL_FID,           // 13

    // Total number of metadata fields, always first after actual FIDs.
    NUM_METADATA_FIELDS,    // 14

    // Number of CHP fields, always 1 past RSP_BODY_FIELD
    NUM_HTTP_FIELDS = MISC_VIA_FID,
    MAX_KEY_PATTERN = REQ_URI_FID,     // DO NOT CHANGE, used in CHP
};

enum AppidSessionDirection
{
    APP_ID_FROM_INITIATOR,
    APP_ID_FROM_RESPONDER,
    APP_ID_APPID_SESSION_DIRECTION_MAX
};

enum ClientAppDetectType
{
    CLIENT_APP_DETECT_APPID = 0,
    CLIENT_APP_DETECT_TLS_FP
};

#endif
