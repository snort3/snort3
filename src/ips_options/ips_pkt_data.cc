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
// ips_options.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

#define s_name "pkt_data"

static THREAD_LOCAL ProfileStats pktDataPerfStats;

class PktDataOption : public IpsOption
{
public:
    PktDataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_RAW; }

    EvalStatus eval(Cursor&, Packet*) override;
};

IpsOption::EvalStatus PktDataOption::eval(Cursor& c, Packet* p)
{
    Profile profile(pktDataPerfStats);

    c.reset(p);
    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set the detection cursor to the normalized packet data"

class PktDataModule : public Module
{
public:
    PktDataModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &pktDataPerfStats; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new PktDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* pkt_data_ctor(Module*, OptTreeNode*)
{
    return new PktDataOption;
}

static void pkt_data_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi pkt_data_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    pkt_data_ctor,
    pkt_data_dtor,
    nullptr
};

const BaseApi* ips_pkt_data = &pkt_data_api.base;

