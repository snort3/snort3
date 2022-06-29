//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/base_api.h"
#include "main/snort_types.h"
#include "packet_io/active_action.h"

// this is the current version of the api
#define ACTAPI_VERSION ((BASE_API_VERSION << 16) | 1)

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

struct OptTreeNode;
namespace snort
{
struct Packet;

class SO_PUBLIC IpsAction
{
public:
    enum IpsActionPriority : uint16_t
    {
        IAP_OTHER = 1,
        IAP_LOG = 10,
        IAP_ALERT = 20,
        IAP_REWRITE = 30,
        IAP_DROP = 40,
        IAP_BLOCK = 50,
        IAP_REJECT = 60,
        IAP_PASS = 70,
        IAP_MAX = IAP_PASS
    };

public:
    virtual ~IpsAction() = default;
    const char* get_name() const { return name; }
    ActiveAction* get_active_action() const { return active_action; }

    virtual void exec(Packet*, const OptTreeNode* otn = nullptr) = 0;
    virtual bool drops_traffic() { return false; }

protected:
    IpsAction(const char* s, ActiveAction* a)
    {
        active_action = a;
        name = s;
    }

private:
    const char* name;
    ActiveAction* active_action;
};

typedef void (* IpsActFunc)();
typedef IpsAction* (* ActNewFunc)(class Module*);
typedef void (* ActDelFunc)(IpsAction*);

struct ActionApi
{
    BaseApi base;

    IpsAction::IpsActionPriority priority;

    IpsActFunc pinit;
    IpsActFunc pterm;
    IpsActFunc tinit;
    IpsActFunc tterm;

    ActNewFunc ctor;
    ActDelFunc dtor;
};
}
#endif

