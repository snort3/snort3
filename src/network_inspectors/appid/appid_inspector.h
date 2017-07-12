//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_inspector.h author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifndef APPID_INSPECTOR_H
#define APPID_INSPECTOR_H

#include "appid_config.h"
#include "application_ids.h"
#include "flow/flow.h"

class AppIdStatistics;
struct Packet;
class SipEventHandler;
struct SnortConfig;

class AppIdInspector : public Inspector
{
public:

    AppIdInspector(const AppIdModuleConfig*);
    ~AppIdInspector();
    static AppIdInspector* get_inspector();

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;
    void tinit() override;
    void tterm() override;
    void eval(Packet*) override;
    AppIdConfig* get_appid_config();
    AppIdStatistics* get_stats_manager();
    int16_t add_appid_protocol_reference(const char* protocol);

    SipEventHandler& get_sip_event_handler()
    {
        return *my_seh;
    }

private:
    const AppIdModuleConfig* config = nullptr;
    AppIdConfig* active_config = nullptr;
    SipEventHandler* my_seh;

};

int sslAppGroupIdLookup(void*, const char*, const char*, AppId*, AppId*, AppId*);
AppId getOpenAppId(Flow*);

#endif

