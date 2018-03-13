//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// ips_modbus_data.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "modbus_decode.h"

using namespace snort;

static const char* s_name = "modbus_data";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats modbus_data_prof;

class ModbusDataOption : public IpsOption
{
public:
    ModbusDataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;
};

uint32_t ModbusDataOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool ModbusDataOption::operator==(const IpsOption& ips) const
{
    return !strcmp(get_name(), ips.get_name());
}

IpsOption::EvalStatus ModbusDataOption::eval(Cursor& c, Packet* p)
{
    Profile profile(modbus_data_prof);

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    if ( p->dsize < MODBUS_MIN_LEN )
        return NO_MATCH;

    c.set(s_name, p->data + MODBUS_MIN_LEN, p->dsize - MODBUS_MIN_LEN);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set cursor to modbus data"

class ModbusDataModule : public Module
{
public:
    ModbusDataModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &modbus_data_prof; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ModbusDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module*, OptTreeNode*)
{
    return new ModbusDataOption;
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
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
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_modbus_data = &ips_api.base;

