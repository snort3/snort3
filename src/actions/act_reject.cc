/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// act_reject.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "packet_io/active.h"
#include "snort_debug.h"
#include "snort.h"

static const char* s_name = "reject";

//-------------------------------------------------------------------------
// reject module
//-------------------------------------------------------------------------

static const Parameter reject_params[] =
{
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class RejectModule : public Module
{
public:
    RejectModule() : Module(s_name, reject_params) { };
    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

public:
};

bool RejectModule::set(const char*, Value&, SnortConfig*)
{
    return false;
}

bool RejectModule::begin(const char*, int, SnortConfig*)
{
    return true;
}

bool RejectModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------

class RejectAction : public IpsAction
{
public:
    RejectAction(RejectModule*);

    void exec(Packet*);

private:
    unsigned flags;
};

RejectAction::RejectAction(RejectModule*) : 
    IpsAction(s_name)
{
    Active_SetEnabled(1);
}

void RejectAction::exec(Packet* p)
{
    if ( PacketIsRebuilt(p) )
        return;

    Active_QueueReject();
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new RejectModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* rej_ctor(Module* m)
{ return new RejectAction((RejectModule*)m); }

static void rej_dtor(IpsAction* p)
{ delete p; }

static ActionApi rej_api
{
    {
        PT_IPS_ACTION,
        s_name,
        ACTAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    RULE_TYPE__DROP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    rej_ctor,
    rej_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &rej_api.base,
    nullptr
};
#else
const BaseApi* act_reject = &rej_api.base;
#endif

