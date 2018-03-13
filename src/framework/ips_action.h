//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_action.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_ACTION_H
#define IPS_ACTION_H

// IpsAction provides custom rule actions that are executed when a
// detection event is generated regardless of whether the event is logged.
// These can be used to execute external controls like updating an external
// firewall.

#include "actions/actions.h"
#include "framework/base_api.h"
#include "main/snort_types.h"

// this is the current version of the api
#define ACTAPI_VERSION ((BASE_API_VERSION << 16) | 0)

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

namespace snort
{
struct Packet;
struct SnortConfig;

enum ActionType
{
    ACT_LOCAL,
    ACT_MODIFY,
    ACT_PROXY,
    ACT_RESET,
    ACT_REMOTE,
    ACT_MAX
};

class SO_PUBLIC IpsAction
{
public:
    virtual ~IpsAction() = default;

    virtual void exec(Packet*) = 0;

    const char* get_name() const { return name; }
    ActionType get_action() { return action; }

protected:
    IpsAction(const char* s, ActionType a)
    { name = s; action = a; }

private:
    const char* name;
    ActionType action;
};

typedef void (* IpsActFunc)();
typedef IpsAction* (* ActNewFunc)(class Module*);
typedef void (* ActDelFunc)(IpsAction*);

struct ActionApi
{
    BaseApi base;
    Actions::Type type;

    IpsActFunc pinit;
    IpsActFunc pterm;
    IpsActFunc tinit;
    IpsActFunc tterm;

    ActNewFunc ctor;
    ActDelFunc dtor;
};
}
#endif

