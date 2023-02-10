//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <set>

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "app_info_table.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace std;
using namespace snort;

//-------------------------------------------------------------------------
// appid option
//-------------------------------------------------------------------------

#define s_name "appids"
#define s_help \
    "detection option for application ids"

static THREAD_LOCAL ProfileStats ips_appid_perf_stats;

class AppIdIpsOption : public IpsOption
{
public:
    AppIdIpsOption(const set<string> &appid_table) :
        IpsOption(s_name)
    {
        this->appid_table = appid_table;
    }
    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;
    EvalStatus eval(Cursor&, Packet*) override;

private:
    bool match_id_against_rule(OdpContext& odp_ctxt, int32_t id);
    set<string> appid_table;
};

uint32_t AppIdIpsOption::hash() const
{
    uint32_t a = appid_table.size();
    uint32_t b = IpsOption::hash();
    uint32_t c = 0;

    mix(a, b, c);

    for ( auto& appid_name : appid_table )
        mix_str(a, b, c, appid_name.c_str(), appid_name.length());

    finalize(a, b, c);
    return c;
}

bool AppIdIpsOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    return ( appid_table == ((const AppIdIpsOption&)ips).appid_table );
}

bool AppIdIpsOption::match_id_against_rule(OdpContext& odp_ctxt, int32_t id)
{
    if (id <= APP_ID_NONE)
        return false;

    const char *app_name_key = odp_ctxt.get_app_info_mgr().get_app_name_key(id);
    if ( nullptr != app_name_key )
    {
        string app_name(app_name_key);
        if ( appid_table.find(app_name) != appid_table.end() )
            return true;
    }
    return false;
}

// to determine if the application ids in the rule match the flow get the current
// ids for payload/misc/service/client and compare against ids defined on the rule
// first match wins...
IpsOption::EvalStatus AppIdIpsOption::eval(Cursor&, Packet* p)
{
    RuleProfile profile(ips_appid_perf_stats);

    if ( !p->flow )
        return NO_MATCH;

    AppIdSession* session = appid_api.get_appid_session(*(p->flow));

    // Skip detection for sessions using old odp context after odp reload
    if ( !session or !pkt_thread_odp_ctxt or
        (session->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version()))
        return NO_MATCH;

    AppId service_id = session->get_api().get_service_app_id();
    OdpContext& odp_ctxt = session->get_odp_ctxt();

    if ((service_id != APP_ID_HTTP2 and service_id != APP_ID_HTTP3) or
        (service_id == APP_ID_HTTP3 and session->get_api().get_hsessions_size() == 0))
    {
        AppId app_ids[APP_PROTOID_MAX];

        // id order on stream api call is: service, client, payload, misc
        session->get_api().get_first_stream_app_ids(app_ids[APP_PROTOID_SERVICE], app_ids[APP_PROTOID_CLIENT],
            app_ids[APP_PROTOID_PAYLOAD], app_ids[APP_PROTOID_MISC]);

        for ( unsigned i = 0; i < APP_PROTOID_MAX; i++ )
            if (match_id_against_rule(odp_ctxt, app_ids[i]))
                return MATCH;
    }
    else
    {
        if (match_id_against_rule(odp_ctxt, service_id))
            return MATCH;

        for (uint32_t i = 0; i < session->get_api().get_hsessions_size(); i++)
        {
            const AppIdHttpSession* hsession = session->get_http_session(i);
            if (!hsession)
                return NO_MATCH;
            if (match_id_against_rule(odp_ctxt, hsession->client.get_id()))
                return MATCH;
            if (match_id_against_rule(odp_ctxt, hsession->payload.get_id()))
                return MATCH;
            if (match_id_against_rule(odp_ctxt, hsession->misc_app_id))
                return MATCH;
        }
    }

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// appid rule option module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr, "comma separated list of application names" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class AppIdOptionModule : public Module
{
public:
    AppIdOptionModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &ips_appid_perf_stats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    std::set<string> appid_table;
};

bool AppIdOptionModule::begin(const char*, int, SnortConfig*)
{
    appid_table.clear();
    return true;
}

bool AppIdOptionModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("~"));

    v.set_first_token();
    string tok;

    while ( v.get_next_csv_token(tok) )
    {
        if ( tok[0] == '"' )
            tok.erase(0, 1);

        if ( tok[tok.length()-1] == '"' )
            tok.erase(tok.length() - 1, 1);

        char *lcase_tok = AppInfoManager::strdup_to_lower(tok.c_str());
        string app_name(lcase_tok);
        appid_table.emplace(app_name);
        snort_free(lcase_tok);
    }

    return true;
}

bool AppIdOptionModule::end(const char*, int, SnortConfig*)
{
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
    return new AppIdIpsOption(m->appid_table);
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

