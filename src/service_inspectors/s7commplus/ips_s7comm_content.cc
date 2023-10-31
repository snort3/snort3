//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// ips_s7comm_content.cc author Pradeep Damodharan <prdamodh@cisco.com>
// based on work by Jeffrey Gu <jgu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "s7comm_decode.h"

using namespace snort;

static const char* s_name = "s7commplus_content";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7commplus_content_prof;

class S7commplusContentOption : public IpsOption
{
public:
    S7commplusContentOption() : IpsOption(s_name) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FAST_PATTERN; }
};

uint32_t S7commplusContentOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool S7commplusContentOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus S7commplusContentOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(s7commplus_content_prof);   // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    if ( p->dsize < S7COMMPLUS_MIN_HDR_LEN )
        return NO_MATCH;

    c.set(s_name, p->data + S7COMMPLUS_MIN_HDR_LEN, p->dsize - S7COMMPLUS_MIN_HDR_LEN);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set cursor to s7commplus content"

class S7commplusContentModule : public Module
{
public:
    S7commplusContentModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &s7commplus_content_prof; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commplusContentModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module*, OptTreeNode*)
{
    return new S7commplusContentOption;
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

const BaseApi* ips_s7commplus_content = &ips_api.base;

