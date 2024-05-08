//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// ips_js_data.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/inspector.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

using namespace snort;

static constexpr const char* s_name = "js_data";
static constexpr const char* s_help = "rule option to set detection cursor to normalized JavaScript data";

static THREAD_LOCAL ProfileStats js_data_profile_stats;

class JSDataModule : public Module
{
public:
    JSDataModule() : Module(s_name, s_help) { }

    Usage get_usage() const override
    { return DETECT; }

    ProfileStats* get_profile() const override
    { return &js_data_profile_stats; }
};

class JSDataOption : public IpsOption
{
public:
    JSDataOption() : IpsOption(s_name) { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_FAST_PATTERN; }

    section_flags get_pdu_section(bool) const override
    { return section_to_flag(PS_BODY); }

    EvalStatus eval(Cursor& c, Packet* p) override
    {
        // cppcheck-suppress unreadVariable
        RuleProfile profile(js_data_profile_stats);
        InspectionBuffer buf;

        if (!p->flow or !p->flow->gadget)
            return NO_MATCH;

        if (p->flow->gadget->get_fp_buf(buf.IBT_JS_DATA, p, buf))
        {
            c.set(s_name, buf.data, buf.len);
            return MATCH;
        }

        return NO_MATCH;
    }
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new JSDataModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsOption* js_data_ctor(Module*, IpsInfo&)
{ return new JSDataOption; }

static void js_data_dtor(IpsOption* opt)
{ delete opt; }

static const IpsApi js_data_api =
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
    js_data_ctor,
    js_data_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_js_data[] =
#endif
{
    &js_data_api.base,
    nullptr
};
