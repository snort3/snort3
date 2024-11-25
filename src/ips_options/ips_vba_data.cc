//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_vba_data.cc author Amarnath Nayak <amarnaya@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_vba_data.h"

#include "framework/module.h"

using namespace snort;

THREAD_LOCAL const Trace* vba_data_trace = nullptr;

LiteralSearch::Handle* search_handle = nullptr;
const LiteralSearch* searcher = nullptr;

CursorActionType VbaDataOption::get_cursor_type() const
{ return CAT_SET_FAST_PATTERN; }

IpsOption::EvalStatus VbaDataOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(vbaDataPerfStats);

    if (!p->flow or !p->flow->gadget)
        return NO_MATCH;

    InspectionBuffer buf;
    if (!p->flow->gadget->get_fp_buf(buf.IBT_VBA, p, buf))
        return NO_MATCH;

    c.set(s_name, buf.data, buf.len);
    return MATCH;
}

bool VbaDataModule::end(const char*, int, SnortConfig*)
{
    if (!search_handle)
        search_handle = LiteralSearch::setup();

    if (!searcher)
        searcher = snort::LiteralSearch::instantiate(search_handle,
            (const uint8_t*)"ATTRIBUT", 8, true);

    return true;
}

VbaDataModule::~VbaDataModule()
{
    if (searcher)
    {
        delete searcher;
        searcher = nullptr;
    }

    if (search_handle)
    {
        LiteralSearch::cleanup(search_handle);
        search_handle = nullptr;
    }
}

ProfileStats* VbaDataModule::get_profile() const
{ return &vbaDataPerfStats; }

void VbaDataModule::set_trace(const Trace* trace) const
{ vba_data_trace = trace; }


const TraceOption* VbaDataModule::VbaDataModule::get_trace_options() const
{
    static const TraceOption vba_data_trace_options(nullptr, 0, nullptr);
    return &vba_data_trace_options;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------


static Module* mod_ctor()
{
    return new VbaDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* vba_data_ctor(Module*, IpsInfo&)
{
    return new VbaDataOption;
}

static void vba_data_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi vba_data_api =
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
    vba_data_ctor,
    vba_data_dtor,
    nullptr
};

const BaseApi* ips_vba_data[] =
{
    &vba_data_api.base,
    nullptr
};

//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------
#ifdef UNIT_TEST

#include "catch/snort_catch.h"
#include "main/policy.h"

TEST_CASE("vba_data test", "[ips_vba_data]")
{
    VbaDataOption vba_data_opt;
    Packet p;
    p.data = (const uint8_t*) "foo";
    p.dsize = strlen((const char*) p.data);

    SECTION("null flow")
    {
        p.flow = nullptr;

        Cursor c(&p);
        REQUIRE(vba_data_opt.eval(c, &p) == IpsOption::NO_MATCH);
    }

    SECTION("null gadget")
    {
        Flow* f = new Flow();
        InspectionPolicy ins;
        set_inspection_policy(&ins);
        NetworkPolicy net;
        set_network_policy(&net);

        p.flow = f;
        p.flow->gadget = nullptr;

        Cursor c(&p);
        REQUIRE(vba_data_opt.eval(c, &p) == IpsOption::NO_MATCH);

        delete f;
    }
}

#endif
