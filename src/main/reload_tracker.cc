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
// reload_tracker.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reload_tracker.h"

#include <cassert>

#include "control/control.h"
#include "log/messages.h"

using namespace snort;

bool ReloadTracker::reload_in_progress = false;
std::string ReloadTracker::current_command;
ControlConn* ReloadTracker::ctrl = nullptr;

bool ReloadTracker::start(ControlConn* ctrlcon)
{
    if (reload_in_progress)
    {
        LogMessage("Reload in progress [%s], attempting command: [%s]\n",
            current_command.c_str(),
            ctrlcon ? ctrlcon->get_current_command().substr(0, 50).c_str() : "signal");
        return false;
    }
    reload_in_progress = true;
    current_command = (ctrlcon ? ctrlcon->get_current_command().substr(0, 50) : "signal");
    LogMessage("Reload started. [%s]\n", current_command.c_str());
    ctrl = ctrlcon;
    return true;
}

void ReloadTracker::end(const ControlConn* ctrlcon, bool prompt)
{
#ifdef NDEBUG
    UNUSED(ctrlcon);
#else
    assert(ctrl == ctrlcon and reload_in_progress);
#endif
    LogMessage("Reload ended. [%s]\n", current_command.c_str());
    current_command.clear();
    if (prompt)
        ctrl->show_prompt();
    ctrl = nullptr;
    reload_in_progress = false;
}

void ReloadTracker::failed(const ControlConn* ctrlcon, const char* reason)
{
#ifdef NDEBUG
    UNUSED(ctrlcon);
#else
    assert(ctrl == ctrlcon and reload_in_progress);
#endif
    LogMessage("Reload failed! %s [%s]\n", reason, current_command.c_str());
    current_command.clear();
    ctrl = nullptr;
    reload_in_progress = false;
}

void ReloadTracker::update(const ControlConn* ctrlcon, const char* status)
{
#ifdef NDEBUG
    UNUSED(ctrlcon);
#else
    assert(ctrl == ctrlcon and reload_in_progress);
#endif
    LogMessage("Reload update: %s [%s]\n", status, current_command.c_str());
}
