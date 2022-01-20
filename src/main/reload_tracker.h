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
// reload_tracker.h author Steven Baigal <sbaigal@cisco.com>

#ifndef RELOAD_TRACKER_H
#define RELOAD_TRACKER_H

#include <string>

#include "main/snort_types.h"

class ControlConn;

namespace snort
{

class SO_PUBLIC ReloadTracker
{
public:
    ReloadTracker() = delete;
    static bool start(ControlConn* ctrlcon);
    static void end(ControlConn* ctrlcon);
    static void failed(ControlConn* ctrlcon, const char* reason);
    static void update(ControlConn* ctrlcon, const char* status);

private:
    static bool reload_in_progress;
    static std::string current_command;
    static ControlConn* ctrl;
};

}

#endif
