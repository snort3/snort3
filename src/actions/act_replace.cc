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
// act_replace.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "act_replace.h"

#include "detection/detection_engine.h"
#include "framework/ips_action.h"
#include "framework/module.h"
#include "packet_io/active.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "rewrite"

#define s_help \
    "overwrite packet contents"

//--------------------------------------------------------------------------
// queue foo
//--------------------------------------------------------------------------

void Replace_ResetQueue()
{
    DetectionEngine::clear_replacement();
}

void Replace_QueueChange(const std::string& s, unsigned off)
{
    DetectionEngine::add_replacement(s, off);
}

static inline void Replace_ApplyChange(Packet* p, std::string& data, unsigned offset)
{
    uint8_t* start = const_cast<uint8_t*>(p->data) + offset;
    const uint8_t* end = p->data + p->dsize;
    unsigned len;

    if ( (start + data.size()) >= end )
        len = p->dsize - offset;
    else
        len = data.size();

    memcpy(start, data.c_str(), len);
}

static void Replace_ModifyPacket(Packet* p)
{
    std::string data;
    unsigned offset;
    bool modified = false;

    while ( DetectionEngine::get_replacement(data, offset) )
    {
        modified = true;
        Replace_ApplyChange(p, data, offset);
    }

    if ( modified )
        p->packet_flags |= PKT_MODIFIED;

    DetectionEngine::clear_replacement();
}

//-------------------------------------------------------------------------
// replace module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "disable_replace", Parameter::PT_BOOL, nullptr, "false",
      "disable replace of packet contents with rewrite rules" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReplaceModule : public Module
{
public:
    ReplaceModule() : Module(s_name, s_help, s_params) { }
    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return DETECT; }

public:
    bool disable_replace;
};

bool ReplaceModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("disable_replace") )
        disable_replace = v.get_bool();
    else
        return false;

    return true;
}

bool ReplaceModule::begin(const char*, int, SnortConfig*)
{
    disable_replace = false;
    return true;
}

bool ReplaceModule::end(const char*, int, SnortConfig*)
{
    return true;
}

//-------------------------------------------------------------------------

class ReplaceAction : public IpsAction
{
public:
    ReplaceAction(ReplaceModule*);

    void exec(Packet*) override;
private:
    bool disable_replace = false;
};

ReplaceAction::ReplaceAction(ReplaceModule* m) :
    IpsAction(s_name, ACT_RESET)
{
    disable_replace = m->disable_replace;
    Active::set_enabled();
}

void ReplaceAction::exec(Packet* p)
{
    if ( p->is_rebuilt() || disable_replace )
        return;

    Replace_ModifyPacket(p);
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ReplaceModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsAction* rep_ctor(Module* m)
{ return new ReplaceAction((ReplaceModule*)m); }

static void rep_dtor(IpsAction* p)
{ delete p; }

static ActionApi rep_api
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    Actions::ALERT,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    rep_ctor,
    rep_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* act_replace[] =
#endif
{
    &rep_api.base,
    nullptr
};

