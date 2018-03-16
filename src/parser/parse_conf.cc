//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "parse_conf.h"

#include <sys/stat.h>

#include <fstream>
#include <stack>

#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/action_manager.h"
#include "sfip/sf_vartable.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "config_file.h"
#include "parser.h"
#include "parse_stream.h"
#include "vars.h"

using namespace snort;

struct Location
{
    std::string file;
    unsigned line;

    Location(const char* s, unsigned u)
    { file = s; line = u; }
};

static std::stack<Location> files;

void get_parse_location(const char*& file, unsigned& line)
{
    if ( files.empty() )
    {
        file = nullptr;
        line = 0;
        return;
    }
    Location& loc = files.top();
    file = loc.file.c_str();
    line = loc.line;
}

void push_parse_location(const char* file, unsigned line)
{
    if ( !file )
        return;

    Location loc(file, line);
    files.push(loc);
    LogMessage("Loading %s:\n", file);
}

void pop_parse_location()
{
    if ( !files.empty() )
    {
        Location& loc = files.top();
        LogMessage("Finished %s.\n", loc.file.c_str());
        files.pop();
    }
}

void inc_parse_position()
{
    Location& loc = files.top();
    ++loc.line;
}

void parse_include(SnortConfig* sc, const char* arg)
{
    struct stat file_stat;  /* for include path testing */
    arg = ExpandVars(sc, arg);
    char* fname = snort_strdup(arg);

    /* Stat the file.  If that fails, make it relative to the directory
     * that the top level snort configuration file was in */
    if ( stat(fname, &file_stat) == -1 && fname[0] != '/' )
    {
        const char* snort_conf_dir = get_snort_conf_dir();

        int path_len = strlen(snort_conf_dir) + strlen(arg) + 1;
        snort_free(fname);

        fname = (char*)snort_calloc(path_len);
        snprintf(fname, path_len, "%s%s", snort_conf_dir, arg);
    }

    push_parse_location(fname);
    ParseConfigFile(sc, fname);
    pop_parse_location();
    snort_free((char*)fname);
}

void ParseIpVar(SnortConfig* sc, const char* var, const char* val)
{
    int ret;
    IpsPolicy* p = get_ips_policy();  // FIXIT-M double check, see below
    DisallowCrossTableDuplicateVars(sc, var, VAR_TYPE__IPVAR);

    if ((ret = sfvt_define(p->ip_vartable, var, val)) != SFIP_SUCCESS)
    {
        switch (ret)
        {
        case SFIP_ARG_ERR:
            ParseError("the following is not allowed: %s.", val);
            return;

        case SFIP_DUPLICATE:
            ParseWarning(WARN_VARS, "Var '%s' redefined.", var);
            break;

        case SFIP_CONFLICT:
            ParseError("negated IP ranges that are more general than "
                "non-negated ranges are not allowed. Consider "
                "inverting the logic in %s.", var);
            return;

        case SFIP_NOT_ANY:
            ParseError("!any is not allowed in %s.", var);
            return;

        default:
            ParseError("failed to parse the IP address: %s.", val);
            return;
        }
    }
}

void add_service_to_otn(SnortConfig* sc, OptTreeNode* otn, const char* svc_name)
{
    if (otn->sigInfo.num_services >= sc->max_metadata_services)
    {
        ParseError("too many service's specified for rule, can't add %s", svc_name);
        return;
    }
    SnortProtocolId svc_id = sc->proto_ref->add(svc_name);

    for ( unsigned i = 0; i < otn->sigInfo.num_services; ++i )
        if ( otn->sigInfo.services[i].snort_protocol_id == svc_id )
            return;  // already added

    if ( !otn->sigInfo.services )
        otn->sigInfo.services =
            (SignatureServiceInfo*)snort_calloc(sc->max_metadata_services, sizeof(SignatureServiceInfo));

    int idx = otn->sigInfo.num_services++;

    otn->sigInfo.services[idx].service = snort_strdup(svc_name);
    otn->sigInfo.services[idx].snort_protocol_id = svc_id;
}

// only keep drop rules ...
// if we are inline (and can actually drop),
// or we are going to just alert instead of drop,
// or we are going to ignore session data instead of drop.
// the alert case is tested for separately with SnortConfig::treat_drop_as_alert().
static inline int ScKeepDropRules()
{
    return ( SnortConfig::inline_mode() || SnortConfig::adaptor_inline_mode() || SnortConfig::treat_drop_as_ignore() );
}

static inline int ScLoadAsDropRules()
{
    return ( SnortConfig::inline_test_mode() || SnortConfig::adaptor_inline_test_mode() );
}

Actions::Type get_rule_type(const char* s)
{
    Actions::Type rt = Actions::get_type(s);

    if ( rt == Actions::NONE )
        rt = ActionManager::get_action_type(s);

    switch ( rt )
    {
    case Actions::DROP:
    case Actions::BLOCK:
    case Actions::RESET:
        if ( SnortConfig::treat_drop_as_alert() )
            return Actions::ALERT;

        if ( ScKeepDropRules() || ScLoadAsDropRules() )
            return rt;

        return Actions::NONE;

    case Actions::NONE:
        ParseError("unknown rule type '%s'", s);
        break;

    default:
        break;
    }
    return rt;
}

ListHead* get_rule_list(SnortConfig* sc, const char* s)
{
    const RuleListNode* p = sc->rule_lists;

    while ( p && strcmp(p->name, s) )
        p = p->next;

    return p ? p->RuleList : nullptr;
}

void AddRuleState(SnortConfig* sc, const RuleState& rs)  // FIXIT-L move to snort config
{
    if (sc == nullptr)
        return;

    RuleState* state = (RuleState*)snort_calloc(sizeof(RuleState));
    *state = rs;

    if ( !sc->rule_state_list )
    {
        sc->rule_state_list = state;
    }
    else
    {
        state->next = sc->rule_state_list;
        sc->rule_state_list = state;
    }
}

void ParseConfigFile(SnortConfig* sc, const char* fname)
{
    if ( !fname )
        return;

    std::ifstream fs(fname, std::ios_base::binary);

    if ( !fs )
    {
        ParseError("unable to open rules file '%s': %s",
            fname, get_error(errno));
        return;
    }
    parse_stream(fs, sc);
}

void ParseConfigString(SnortConfig* sc, const char* s)
{
    std::string rules = s;
    std::stringstream ss(rules);
    parse_stream(ss, sc);
}

