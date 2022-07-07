//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <unistd.h>

#include <cassert>
#include <climits>
#include <fstream>
#include <stack>

#include "detection/fp_utils.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
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
    const char* code;
    std::string path;
    std::string file;
    unsigned line;

    Location(const char* c, const char* p, const char* f, unsigned u)
    { code = c; path = p; file = f; line = u; }
};

static std::stack<Location> files;
static int rules_file_depth = 0;
static bool s_ips_policy = true;

const char* get_parse_file()
{
    if ( !files.empty() )
        return files.top().path.c_str();

    return get_snort_conf();
}

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

static void print_parse_file(const char* msg, Location& loc)
{
    if ( SnortConfig::get_conf()->show_file_codes() )
        LogMessage("%s %s:%s:\n", msg, (loc.code ? loc.code : "?"), loc.file.c_str());

    else
        LogMessage("%s %s:\n", msg, loc.file.c_str());
}

void push_parse_location(
    const char* code, const char* path, const char* file, unsigned line)
{
    if ( !path )
        return;

    if ( !file )
        file = path;

    Location loc(code, path, file, line);
    files.push(loc);
    print_parse_file("Loading", loc);
}

void pop_parse_location()
{
    if ( !files.empty() )
    {
        Location& loc = files.top();
        print_parse_file("Finished", loc);
        files.pop();
    }
}

void inc_parse_position()
{
    if ( files.empty() )
        return;
    Location& loc = files.top();
    ++loc.line;
}

static bool valid_file(const char* file, std::string& path)
{
    path += '/';
    path += file;

    struct stat s;
    return stat(path.c_str(), &s) == 0;
}

static bool relative_to_parse_dir(const char* file, std::string& path)
{
    if ( !path.length() )
        path = get_parse_file();
    size_t idx = path.rfind('/');
    if ( idx != std::string::npos )
        path.erase(idx);
    else
        path = ".";
    return valid_file(file, path);
}

static bool relative_to_config_dir(const char* file, std::string& path)
{
    path = get_snort_conf_dir();
    return valid_file(file, path);
}

static bool relative_to_include_dir(const char* file, std::string& path)
{
    path = SnortConfig::get_conf()->include_path;
    if ( !path.length() )
        return false;
    return valid_file(file, path);
}

const char* get_config_file(const char* arg, std::string& file)
{
    assert(arg);

    bool absolute = (arg[0] == '/');

    if ( absolute )
    {
        file = arg;
        return "A";
    }
    std::string hint = file;

    if ( relative_to_include_dir(arg, file) )
        return "I";

    file = hint;

    if ( relative_to_parse_dir(arg, file) )
        return "F";

    if ( relative_to_config_dir(arg, file) )
        return "C";

    return nullptr;
}

void parse_include(SnortConfig* sc, const char* arg)
{
    assert(arg);
    std::string conf = ExpandVars(arg);
    std::string file;

    if ( rules_file_depth )
        file = get_parse_file();

    else if ( s_ips_policy )
        file = get_ips_policy()->includer;

    else
        file = parser_get_special_includer();

    const char* code = get_config_file(conf.c_str(), file);

    if ( !code )
    {
        ParseError("can't open %s\n", conf.c_str());
        return;
    }
    push_parse_location(code, file.c_str(), conf.c_str());
    parse_rules_file(sc, file.c_str());
    pop_parse_location();
}

void ParseIpVar(const char* var, const char* value)
{
    int ret;
    IpsPolicy* p = get_ips_policy();
    DisallowCrossTableDuplicateVars(var, VAR_TYPE__IPVAR); 
    // FIXIT-M: ip checked for duplicates twice: in the function above and in sfvt_add_str

    if ((ret = sfvt_define(p->ip_vartable, var, value)) != SFIP_SUCCESS)
    {
        switch (ret)
        {
        case SFIP_ARG_ERR:
            ParseError("the following is not allowed: %s.", value);
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
            ParseError("failed to parse the IP address: %s.", value);
            return;
        }
    }
}

void add_service_to_otn(SnortConfig* sc, OptTreeNode* otn, const char* svc_name)
{
    if ( !strcmp(svc_name, "file") and otn->sigInfo.services.empty() )
    {
        // well-known services supporting file_data
        // applies to both alert file and service:file rules
        std::string buf = "file_data";
        add_default_services(sc, buf, otn);
        add_service_to_otn(sc, otn, "file");
        return;
    }

    if ( !strcmp(svc_name, "http") )
        add_service_to_otn(sc, otn, "http2");

    SnortProtocolId svc_id = sc->proto_ref->add(svc_name);

    for ( const auto& si : otn->sigInfo.services )
        if ( si.snort_protocol_id == svc_id )
            return;  // already added

    SignatureServiceInfo si(svc_name, svc_id);
    otn->sigInfo.services.emplace_back(si);
}

ListHead* get_rule_list(SnortConfig* sc, const char* s)
{
    const RuleListNode* p = sc->rule_lists;

    while ( p && strcmp(p->name, s) )
        p = p->next;

    return p ? p->RuleList : nullptr;
}

void parse_rules_file(SnortConfig* sc, const char* fname)
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
    ++rules_file_depth;
    parse_stream(fs, sc);
    --rules_file_depth;
}

void parse_rules_string(SnortConfig* sc, const char* s, bool ips_policy)
{
    s_ips_policy = ips_policy;
    std::string rules = s;
    std::stringstream ss(rules);
    parse_stream(ss, sc);
    s_ips_policy = true;
}

