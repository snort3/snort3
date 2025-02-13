//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// ips_dnp3_data.cc author Maya Dagon <mdagon@cisco.com>
// based on work by Ryan Jordan

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "dnp3.h"

using namespace snort;

#define s_name "dnp3_data"
#define s_help \
    "sets the cursor to dnp3 data"

//-------------------------------------------------------------------------
// DNP3 data rule option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats dnp3_data_perf_stats;

class Dnp3DataOption : public IpsOption
{
public:
    Dnp3DataOption() : IpsOption(s_name) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FAST_PATTERN; }
};

uint32_t Dnp3DataOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool Dnp3DataOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus Dnp3DataOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(dnp3_data_perf_stats);

    InspectionBuffer b;
    if (!get_buf_dnp3_data(p, b))
        return NO_MATCH;

    c.set(s_name, b.data, b.len);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class Dnp3DataModule : public Module
{
public:
    Dnp3DataModule() : Module(s_name, s_help) { }
    ProfileStats* get_profile() const override;

    Usage get_usage() const override
    { return DETECT; }
};

ProfileStats* Dnp3DataModule::get_profile() const
{
    return &dnp3_data_perf_stats;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* dnp3_data_mod_ctor()
{
    return new Dnp3DataModule;
}

static void dnp3_data_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dnp3_data_ctor(Module*, IpsInfo&)
{
    return new Dnp3DataOption;
}

static void dnp3_data_dtor(IpsOption* p)
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
        dnp3_data_mod_ctor,
        dnp3_data_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    dnp3_data_ctor,
    dnp3_data_dtor,
    nullptr
};

const BaseApi* ips_dnp3_data = &ips_api.base;

