//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// appid_ssh_event_handler.h  author Daniel McGarvey <danmcgar@cisco.com>

#ifndef APPID_SSH_EVENT_HANDLER_H
#define APPID_SSH_EVENT_HANDLER_H

#include "pub_sub/ssh_events.h"

#include "appid_module.h"

class SshEventHandler : public snort::DataHandler
{
public:
    SshEventHandler() : snort::DataHandler(MOD_NAME) 
    { id = snort::FlowData::create_flow_data_id(); }

    void handle(snort::DataEvent &, snort::Flow *) override;

private:
    static unsigned int id;
};

struct SshAppIdInfo
{
    std::string vendor;
    std::string version;
    bool finished = false;
};

struct SshEventFlowData
{
    SshAppIdInfo service_info;
    SshAppIdInfo client_info;
    bool failed = false;
};

#endif
