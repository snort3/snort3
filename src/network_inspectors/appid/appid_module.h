//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

// appid_module.h author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifndef APPID_MODULE_H
#define APPID_MODULE_H

#include "main/snort_types.h"
#include "framework/module.h"
#include "appid_config.h"

extern THREAD_LOCAL ProfileStats appidPerfStats;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

#define MOD_NAME "appid"
#define MOD_HELP "application and service identification"

struct AppIdStats
{
    PegCount packets;
    PegCount dns_udp_flows;
    PegCount dns_tcp_flows;
    PegCount ftp_flows;
    PegCount ftps_flows;
    PegCount smtp_flows;
    PegCount smtps_flows;
    PegCount ssl_flows;
    PegCount telnet_flows;
};

extern THREAD_LOCAL AppIdStats appid_stats;

class AppIdModule : public Module
{
public:
    AppIdModule();
    ~AppIdModule();

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    const AppIdModuleConfig* get_data();

private:
    AppIdModuleConfig* config;
};

#endif
