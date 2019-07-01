//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// flow_stash_keys.h author Deepak Ramadass <deramada@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef FLOW_STASH_KEYS_H
#define FLOW_STASH_KEYS_H

enum FlowStashKey
{
    STASH_APPID_SERVICE = 0,
    STASH_APPID_CLIENT,
    STASH_APPID_PAYLOAD,
    STASH_APPID_MISC,
    STASH_APPID_REFERRED,
 
    STASH_HOST,
    STASH_TLS_HOST,
    STASH_URL,
    STASH_USER_AGENT,
    STASH_RESPONSE_CODE,
    STASH_REFERER,
    STASH_XFF,
    STASH_CLIENT_VERSION,

    STASH_MAX_SIZE
};

static const char* FlowStashKeyNames[] =
{
    "appid-service",
    "appid-client",
    "appid-payload",
    "appid-misc",
    "appid-referred",
    "host",
    "tls-host",
    "url",
    "user-agent",
    "response-code",
    "referer",
    "xff",
    "client-version"
};

inline const char * get_key_name( int key )
{
    return FlowStashKeyNames[key];
}
#endif
