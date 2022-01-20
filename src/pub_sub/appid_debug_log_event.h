//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// appid_debug_log_event.h author Cliff Judge <cljudge@cisco.com>

#ifndef APPID_DEBUG_LOG_EVENT_H
#define APPID_DEBUG_LOG_EVENT_H

#include <string>

#include "framework/data_bus.h"
#include "network_inspectors/appid/appid_debug.h"

#define APPID_DEBUG_LOG_EVENT "appid_debug_log_event"

class AppIdDebugLogEvent : public snort::DataEvent
{
public:
    AppIdDebugLogEvent(const AppIdDebugSessionConstraints* constraints, const char* dbg_str) :
        cs(constraints), debug_str(dbg_str) { }

    const AppIdDebugSessionConstraints* get_appid_debug_constraints() const
    {
        return cs;
    }

    const std::string& get_debug_string() const
    {
        return debug_str;
    }
private:
    const AppIdDebugSessionConstraints* cs = nullptr;
    std::string debug_str;
};

#endif
