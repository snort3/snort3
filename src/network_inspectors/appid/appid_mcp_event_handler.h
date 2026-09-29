//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifndef APPID_MCP_EVENT_HANDLER_H
#define APPID_MCP_EVENT_HANDLER_H

#include "application_ids.h"
#include "framework/data_bus.h"

class AppIdInspector;

class AppIdMcpEventHandler : public snort::DataHandler
{
public:
    explicit AppIdMcpEventHandler(AppIdInspector&);

    void handle(snort::DataEvent&, snort::Flow*) override;

private:
    AppIdInspector& inspector;
};

#endif
