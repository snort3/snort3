//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_nap_selector.cc author Carter Waxman <cwaxman@cisco.com>

#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/parse_cmd_line.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{

class NapRulesState : public ConversionState
{
public:
    NapRulesState(Converter& c) : ConversionState(c) { }

    // We only care about rules. Format:
    // <id> <action> <zone> <net <netmask>> <port> <zone> <net <netmask>> <port> <vlan> <proto>
    bool convert(std::istringstream& data_stream) override
    {
#define TRY_FIELD(field) \
        if ( !(data_stream >> (field)) ) \
        { \
            data_api.failed_conversion(data_stream, "missing " #field); \
            return false; \
        }

        unsigned rule_id;
        if ( data_stream >> rule_id ) // is this a comment or config
        {
            std::string action;
            std::string src_zone, src_net, src_netmask, src_port;
            std::string dst_zone, dst_net, dst_netmask, dst_port;
            std::string vlan;
            std::string protocol;
            std::string ips_policy;

            TRY_FIELD(action);   // ignore since nap rules don't drop
            TRY_FIELD(src_zone);
            TRY_FIELD(src_net);
            if ( src_net != "any" )
                TRY_FIELD(src_netmask);

            TRY_FIELD(src_port);
            TRY_FIELD(dst_zone);
            TRY_FIELD(dst_net);
            if ( dst_net != "any" )
                TRY_FIELD(dst_netmask);

            TRY_FIELD(dst_port);
            TRY_FIELD(vlan);
            TRY_FIELD(protocol);

            for ( std::string s; data_stream >> s; ips_policy += " " + s );

            if ( ips_policy.empty() )
            {
                data_api.failed_conversion(data_stream, "missing policy");
                return false;
            }

            // parse (ipspolicy 123)
            for ( auto& c : ips_policy )
            {
                if ( c == '(' || c == ')' )
                    c = ' ';
            }

            std::istringstream policy_stream(ips_policy);
            std::string token;

            if ( !(policy_stream >> token) || token != "ipspolicy" )
            {
                data_api.failed_conversion(data_stream, "missing \"ipspolicy\"");
                return false;
            }

            unsigned policy_id;
            if ( !(policy_stream >> policy_id) )
            {
                data_api.failed_conversion(data_stream, "missing or invalid policy_id");
                return false;
            }

            auto seen = rule_map.find(rule_id);
            auto& bind = seen == rule_map.end() ? cv.make_pending_binder(policy_id) : *seen->second;

            bind.set_priority(order++);

            if ( src_zone != "any" )
                bind.set_when_src_zone(src_zone);

            if ( src_net != "any" )
                bind.add_when_src_net(src_net + '/' + src_netmask);

            if ( src_port != "any" )
                bind.add_when_src_port(src_port);

            if ( dst_zone != "any" )
                bind.set_when_dst_zone(dst_zone);

            if ( dst_net != "any" )
                bind.add_when_dst_net(dst_net + '/' + dst_netmask);

            if ( dst_port != "any" )
                bind.add_when_dst_port(dst_port);

            if ( vlan != "any" )
                bind.add_when_vlan(vlan);

            if ( protocol != "any" )
                bind.set_when_proto(protocol);

            rule_map[rule_id] = &bind;
        }
        else
        {
            data_stream.clear();

            std::string keyword;
            if ( data_stream >> keyword )
            {
                cv.get_table_api().open_top_level_table("binder"); // for adding comments
                cv.get_table_api().add_unsupported_comment("nap rules " + keyword);
                cv.get_table_api().close_table();
            }

            while ( data_stream >> keyword );
        }

        return true;
    }

private:
    unsigned order = 0;
    std::unordered_map<unsigned, Binder*> rule_map;
};

class NapSelectorState : public ConversionState
{
public:
    NapSelectorState(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        bool retval = true;
        std::string keyword;

        while ( data_stream >> keyword )
        {
            bool tmpval = true;
            if ( keyword == "nap_rule_path" )
            {
                std::string path;
                if ( data_stream >> path )
                {
                    std::string full_name = data_api.expand_vars(path);
                    std::string full_path = full_name;

                    if (!util::file_exists(full_path))
                        full_path = parser::get_conf_dir() + full_name;

                    if (util::file_exists(full_path))
                    {
                        NapRulesState* s = new NapRulesState(cv);
                        cv.set_state(s, false);
                        // FIXIT-L if there is an error on this line after nap_rule_path
                        // the error message will reference path, not this conf file
                        tmpval = (cv.parse_file(path, nullptr, false) == 0);
                        cv.set_state(this);

                        cv.get_table_api().open_top_level_table("binder");
                        cv.get_table_api().add_diff_option_comment("nap rules", "bindings");
                        cv.get_table_api().close_table();
                    }
                    else
                        tmpval = false;
                }
                else
                {
                    data_api.failed_conversion(data_stream, "nap_rule_path <missing_arg>");
                    tmpval = false;
                }
            }
            else if ( keyword == "nap_stats_time" )
            {
                cv.get_table_api().open_top_level_table("binder");
                cv.get_table_api().add_deleted_comment("nap_stats_time");
                cv.get_table_api().close_table();
                tmpval = eat_option(data_stream);
            }
            else if ( keyword == "fw_required" )
            {
                cv.get_table_api().open_top_level_table("binder");
                cv.get_table_api().add_deleted_comment("fw_required");
                cv.get_table_api().close_table();
            }
            else
                tmpval = false;

            if ( !tmpval )
            {
                data_api.failed_conversion(data_stream, keyword);
                retval = false;
            }
        }
        return retval;
    }
};
} // namespace

static ConversionState* ctor(Converter& c)
{ return new NapSelectorState(c); }

static const ConvertMap nap_selector_api =
{
    "nap_selector",
    ctor,
};

const ConvertMap* nap_selector_map = &nap_selector_api;
} // namespace preprocessors

