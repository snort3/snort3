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

// client_app_config.h author Sourcefire Inc.

#ifndef CLIENT_APP_CONFIG_H
#define CLIENT_APP_CONFIG_H

#include "utils/sflsq.h"
#include "search_engines/search_tool.h"

struct RNAClientAppModule;
struct RNAClientAppRecord;

struct ClientPatternData
{
    ClientPatternData* next;
    int position;
    const RNAClientAppModule* ca;
};

struct ClientAppConfig
{
    RNAClientAppRecord* tcp_client_app_list;    // List of all TCP client apps (C and  Lua)
    RNAClientAppRecord* udp_client_app_list;    // List of all UDP client apps (C and Lua)
    int enabled;
    SF_LIST module_configs;
    ClientPatternData* pattern_data_list;
    SearchTool* tcp_patterns;
    int tcp_pattern_count;
    SearchTool* udp_patterns;
    int udp_pattern_count;
};

#endif
