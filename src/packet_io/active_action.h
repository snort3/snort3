//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// active_action.h author Silviu Minut <sminut@cisco.com>

#ifndef ACTIVE_ACTION_H
#define ACTIVE_ACTION_H

#include "main/snort_types.h"

namespace snort
{
struct Packet;

enum ActionPriority
{
    AP_LOCAL,
    AP_MODIFY,
    AP_PROXY,
    AP_RESET,
    AP_REMOTE,
    AP_MAX
};

// These are injection actions (e.g. send a RST packet, or respond to a query
// with an "Access denied" message). Instances of this class are queued into
// the packet at inspection / detection time and executed at the end by
// Analyzer. The pure virtual exec() method can call into Active methods for
// the low-level stuff.
class SO_PUBLIC ActiveAction
{
public:
    ActiveAction(ActionPriority a = ActionPriority::AP_MAX) : action(a) {}
    virtual ~ActiveAction() = default;

    virtual void delayed_exec(Packet* ) { }

    ActionPriority get_action() const { return action; }

protected:
    ActionPriority action;

};

}

#endif

