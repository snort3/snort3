//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_eve_process_event_handler.h author Cliff Judge <cljudge@cisco.com>

#ifndef APPID_EVE_PROCESS_EVENT_HANDLER_H
#define APPID_EVE_PROCESS_EVENT_HANDLER_H

#include "pub_sub/eve_process_event.h"
#include "appid_module.h"

class AppIdEveProcessEventHandler : public snort::DataHandler
{
public:
    AppIdEveProcessEventHandler(AppIdInspector& inspector) :
        DataHandler(MOD_NAME), inspector(inspector) { }

    void handle(snort::DataEvent& event, snort::Flow* flow) override;

private:
    AppIdInspector& inspector;
};

#endif
