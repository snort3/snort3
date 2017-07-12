//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// ips_appid_option.cc  author: davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "app_info_table.h"
#include "appid_session.h"

#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/sfhashfcn.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

//-------------------------------------------------------------------------
// appid option
//-------------------------------------------------------------------------

#define s_name "appids"
#define s_help \
    "detection option for application ids"

// these defs are used during matching when the rule option eval function is called to
// control the order in which the different id types are checked
#define PAYLOAD    0
#define MISC       1
#define CP_CLIENT  2
#define CP_SERVICE 3
#define SP_CLIENT  3
#define SP_SERVICE 2
#define NUM_ID_TYPES 4

struct AppIdInfo
{
    char* appid_name;
    AppId appid_ordinal;
};

struct AppIdRuleOptionData
{
    std::vector<AppIdInfo> appid_table;
    bool ids_mapped;
};

static THREAD_LOCAL ProfileStats appidRuleOptionPerfStats;

class AppIdIpsOption : public IpsOption
{
public:
    AppIdIpsOption(const AppIdRuleOptionData& c) :
        IpsOption(s_name)
    {
        opt_data = c;
    }

    ~AppIdIpsOption()
    {
        for (auto& appid_info : opt_data.appid_table)
            snort_free(appid_info.appid_name);
    }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    int eval(Cursor&, Packet*) override;

private:
    void map_names_to_ids();
    int match_id_against_rule(int16_t id);

    AppIdRuleOptionData opt_data;
};

uint32_t AppIdIpsOption::hash() const
{
    uint32_t abc[3];

    abc[0] = opt_data.appid_table.size();
    abc[1] = 0;
    abc[2] = 0;

    mix(abc[0], abc[1], abc[2]);

    for ( auto& appid_info : opt_data.appid_table )
        mix_str(abc[0], abc[1], abc[2],
            appid_info.appid_name, strlen(appid_info.appid_name) );

    finalize(abc[0], abc[1], abc[2]);

    return abc[2];
}

bool AppIdIpsOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const AppIdIpsOption& rhs = (AppIdIpsOption&)ips;

    if ( opt_data.appid_table.size() != rhs.opt_data.appid_table.size() )
        return false;

    for (unsigned i = 0; i < opt_data.appid_table.size(); i++)
        if ( strcmp(opt_data.appid_table[i].appid_name, rhs.opt_data.appid_table[i].appid_name) !=
            0)
            return false;

    return true;
}

void AppIdIpsOption::map_names_to_ids()
{
    for (auto& appid_info : opt_data.appid_table)
        appid_info.appid_ordinal = AppInfoManager::get_instance().get_appid_by_name(
            appid_info.appid_name);

    opt_data.ids_mapped = true;
}

int AppIdIpsOption::match_id_against_rule(int16_t id)
{
    for ( auto& appid_info : opt_data.appid_table )
        if ( id == appid_info.appid_ordinal )
            return id;

    return 0;
}

// to determine if the application ids in the rule match the flow get the current
// ids for payload/misc/service/client and compare against ids defined on the rule
// first match wins...
int AppIdIpsOption::eval(Cursor&, Packet* p)
{
    AppId app_ids[NUM_ID_TYPES];

    assert(p->flow);
    Profile profile(appidRuleOptionPerfStats);

    if ( !opt_data.ids_mapped )
        map_names_to_ids();

    AppIdSession* session = appid_api.get_appid_session(p->flow);
    if (!session)
        return DETECTION_OPTION_NO_MATCH;

    // id order on stream api call is: service, client, payload, misc
    if ((p->packet_flags & PKT_FROM_CLIENT))
        session->get_application_ids(app_ids[CP_SERVICE], app_ids[CP_CLIENT],
            app_ids[PAYLOAD], app_ids[MISC]);
    else
        session->get_application_ids(app_ids[SP_SERVICE], app_ids[SP_CLIENT],
            app_ids[PAYLOAD], app_ids[MISC]);

    for ( unsigned i = 0; i < NUM_ID_TYPES; i++ )
        if ( match_id_against_rule(app_ids[i]) )
            return DETECTION_OPTION_MATCH;

    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// appid rule option module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "comma separated list of application names" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static bool compare_appid_names(const AppIdInfo& l, const AppIdInfo& r)
{
    int rc = strcmp(l.appid_name, r.appid_name);
    if ( rc < 0 )
        return true;
    else
        return false;
}

class AppIdOptionModule : public Module
{
public:
    AppIdOptionModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &appidRuleOptionPerfStats; }

    AppIdRuleOptionData opt_data;
};

bool AppIdOptionModule::begin(const char*, int, SnortConfig*)
{
    opt_data.appid_table.clear();
    opt_data.ids_mapped = false;
    return true;
}

bool AppIdOptionModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    v.set_first_token();
    std::string tok;

    while ( v.get_next_csv_token(tok) )
    {
        AppIdInfo appid_info;

        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length() - 1, 1);

        appid_info.appid_name = snort_strdup(tok.c_str());
        appid_info.appid_ordinal = 0;
        opt_data.appid_table.push_back(appid_info);
    }

    return true;
}

bool AppIdOptionModule::end(const char*, int, SnortConfig*)
{
    std::sort(opt_data.appid_table.begin(), opt_data.appid_table.end(), compare_appid_names);
    return true;
}

//-------------------------------------------------------------------------
// appid option api methods
//-------------------------------------------------------------------------

static Module* appid_option_mod_ctor()
{
    return new AppIdOptionModule;
}

static void appid_option_mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* appid_option_ips_ctor(Module* p, OptTreeNode*)
{
    AppIdOptionModule* m = (AppIdOptionModule*)p;
    return new AppIdIpsOption(m->opt_data);
}

static void appid_option_ips_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi appid_option_api =
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
        appid_option_mod_ctor,
        appid_option_mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP | PROTO_BIT__UDP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    appid_option_ips_ctor,
    appid_option_ips_dtor,
    nullptr
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

// added to snort_plugins in appid_inspector.cc
const BaseApi* ips_appid = &appid_option_api.base;

