//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "appid_module.h"
#include "application_ids.h"
#include "flow/flow.h"

namespace snort
{
struct Packet;
struct SnortConfig;
}

class AppIdInspector : public snort::Inspector
{
public:

    AppIdInspector(AppIdModule&);
    ~AppIdInspector() override;

    bool configure(snort::SnortConfig*) override;
    void show(const snort::SnortConfig*) const override;
    void tinit() override;
    void tterm() override;
    void tear_down(snort::SnortConfig*) override;
    void eval(snort::Packet*) override;
    AppIdContext& get_ctxt() const;
    const AppIdConfig& get_config() const { return *config; }

    static unsigned get_pub_id() { return pub_id; }

private:
    const AppIdConfig* config = nullptr;
    AppIdContext* ctxt = nullptr;
    static unsigned pub_id;
};

extern const snort::InspectApi appid_inspector_api;

extern THREAD_LOCAL OdpThreadContext* odp_thread_local_ctxt;
extern THREAD_LOCAL OdpContext* pkt_thread_odp_ctxt;
extern THREAD_LOCAL ThirdPartyAppIdContext* pkt_thread_tp_appid_ctxt;

#endif

