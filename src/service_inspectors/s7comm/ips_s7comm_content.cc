//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

// ips_s7comm_content.cc author Yarin Peretz <yarinp123@gmail.com>
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

#include "s7comm.h"

using namespace snort;

static const char* s_name = "s7comm_content";

//-------------------------------------------------------------------------
// version option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats s7comm_content_prof;

class S7commContentOption : public IpsOption
{
public:
    S7commContentOption() : IpsOption(s_name) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FAST_PATTERN; }
};

uint32_t S7commContentOption::hash() const
{
    uint32_t a = IpsOption::hash(), b = 0, c = 0;

    mix(a, b, c);
    finalize(a,b,c);

    return c;
}

bool S7commContentOption::operator==(const IpsOption& ips) const
{
    return IpsOption::operator==(ips);
}

IpsOption::EvalStatus S7commContentOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(s7comm_content_prof);   // cppcheck-suppress unreadVariable

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    if ( p->dsize < S7COMM_MIN_HDR_LEN )
        return NO_MATCH;

    S7commFlowData* mfd = (S7commFlowData*)p->flow->get_flow_data(S7commFlowData::inspector_id);

    int header_len = S7COMM_MIN_HDR_LEN;

    if (mfd && mfd->ssn_data.s7comm_message_type==ACK_DATA)
    {
        header_len += 2;  // Add the length of error class and error code
    }

    if ( p->dsize < header_len )
        return NO_MATCH;

    c.set(s_name, p->data + header_len, p->dsize - header_len);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

#define s_help \
    "rule option to set cursor to s7comm content"

class S7commContentModule : public Module
{
public:
    S7commContentModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &s7comm_content_prof; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new S7commContentModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module*, IpsInfo&)
{
    return new S7commContentOption;
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

const BaseApi* ips_s7comm_content = &ips_api.base;
