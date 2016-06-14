//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// thirdparty_appid_api.h author Sourcefire Inc.

#ifndef THIRDPARTY_APPID_API_H
#define THIRDPARTY_APPID_API_H

#include "protocols/packet.h"

#include "appid_api.h"
#include "thirdparty_appid_types.h"

#define THIRD_PARTY_APP_ID_API_VERSION 1

#define TP_PATH_MAX 4096

struct ThirdPartyConfig
{
    unsigned chp_body_collection_max;
    unsigned ftp_userid_disabled : 1;
    unsigned chp_body_collection_disabled : 1;
    unsigned tp_allow_probes : 1;
    unsigned http_upgrade_reporting_enabled : 1;
    char appid_tp_dir[TP_PATH_MAX];
    int numXffFields;
    char** xffFields;
    int oldNumXffFields;
    char** oldXffFields;
};

struct ThirdPartyUtils
{
    void (*logMsg)(const char*, ...);
    uint32_t (*getSnortInstance)();
};

using ThirdPartyAppIDModInit = int(*)(ThirdPartyConfig*, ThirdPartyUtils*);
using ThirdPartyAppIDModReconfigure = int(*)(ThirdPartyConfig*);
using ThirdPartyAppIDModFini = int(*)();
using ThirdPartyAppIDSessionCreate = void*(*)();
using ThirdPartyAppIDSessionDelete = int(*)(void* tpsession, int just_reset_state);
// FIXIT-L J use references for output parameters
using ThirdPartyAppIDSessionProcess = int(*)(
    void* tpsession,                                // in
    Packet*,                                        // in
    int direction,                                  // in
    AppId*,                                        // out
    int* confidence,                                // out
    AppId** proto_list,                            // out
    ThirdPartyAppIDAttributeData** attribute_data   // out
);
using ThirdPartyAppIDPrintStats = int(*)();
using ThirdPartyAppIDResetStats = int(*)();
using ThirdPartyAppIDDisableFlags = int(*)(void* tpsession, uint32_t session_flags);
using ThirdPartyAppIDSessionStateGet = TPState(*)(void* tpsession);
using ThirdPartyAppIDSessionStateSet = void(*)(void* tpsession, TPState);
using ThirdPartyAppIDSessionAttrSet = void(*)(void* tpsession, TPSessionAttr);
using ThirdPartyAppIDSessionAttrClear = void(*)(void* tpsession, TPSessionAttr);
using ThirdPartyAppIDSessionAttrGet = unsigned(*)(void* tpsession, TPSessionAttr);
using ThirdPartyAppIDSessionCurrenAppIdGet = AppId(*)(void* tpsession);

// SO_PUBLIC const ThirdPartyAppIDModule thirdparty_appid_impl_module
struct ThirdPartyAppIDModule
{
    const uint32_t api_version;
    const char* module_name;
    ThirdPartyAppIDModInit init;
    ThirdPartyAppIDModReconfigure reconfigure;
    ThirdPartyAppIDModFini fini;
    ThirdPartyAppIDSessionCreate session_create;
    ThirdPartyAppIDSessionDelete session_delete;
    ThirdPartyAppIDSessionProcess session_process;
    ThirdPartyAppIDPrintStats print_stats;
    ThirdPartyAppIDResetStats reset_stats;
    ThirdPartyAppIDDisableFlags disable_flags;

    ThirdPartyAppIDSessionStateGet session_state_get;
    ThirdPartyAppIDSessionStateSet session_state_set;
    ThirdPartyAppIDSessionAttrSet session_attr_set;
    ThirdPartyAppIDSessionAttrClear session_attr_clear;
    ThirdPartyAppIDSessionAttrGet session_attr_get;
    ThirdPartyAppIDSessionCurrenAppIdGet session_appid_get;
};

#endif
