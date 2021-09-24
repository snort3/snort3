//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// ips_js_data.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "profiler/profiler.h"

using namespace snort;

#define s_name "js_data"
#define s_help \
    "rule option to set detection cursor to normalized JavaScript data"

static THREAD_LOCAL ProfileStats scriptDataPerfStats;

class ScriptDataOption : public IpsOption
{
public:
    ScriptDataOption() : IpsOption(s_name, RULE_OPTION_TYPE_BUFFER_SET) { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_SCRIPT; }

    EvalStatus eval(Cursor&, Packet*) override;
};

IpsOption::EvalStatus ScriptDataOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(scriptDataPerfStats);

    DataPointer dp = DetectionEngine::get_js_data(p->context);

    if ( !dp.data or !dp.len )
        return NO_MATCH;

    c.set(s_name, dp.data, dp.len);

    return MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

class ScriptDataModule : public Module
{
public:
    ScriptDataModule() : Module(s_name, s_help) { }

    ProfileStats* get_profile() const override
    { return &scriptDataPerfStats; }

    Usage get_usage() const override
    { return DETECT; }
};

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ScriptDataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* js_data_ctor(Module*, OptTreeNode*)
{
    return new ScriptDataOption;
}

static void js_data_dtor(IpsOption* p)
{
    delete p;
}

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
    0, 0,
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

