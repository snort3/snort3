//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// config_one_int_option.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
/*************************************************
 ************** LUA  STRUCT_NAMES  ***************
 *************************************************/

static const std::string attribute_table = "attribute_table";
static const std::string alerts = "alerts";
static const std::string daq = "daq";
static const std::string detection = "detection";
static const std::string mpls = "mpls";
static const std::string network = "network";
static const std::string output = "output";
static const std::string packets = "packets";
static const std::string process = "process";
static const std::string stream_tcp = "stream_tcp";

// Yes, this looks rather ugly. However, when using Templates,
// I always got warnings.  Since we've got zero tolerance policy
// for such things (and I wanted to keep my checks in Snort2Lua
// for the next developer who comes along)
class ConfigIntOption : public ConversionState
{
public:
    ConfigIntOption(Converter& c,
        const std::string* snort_opt,
        const std::string* table,
        const std::string* lua_opt) :
        ConversionState(c),
        snort_option(snort_opt),
        lua_table(table),
        lua_option(lua_opt)
    {
    }


    bool convert(std::istringstream& stream) override
    {
        if ((snort_option == nullptr) ||
            (snort_option->empty()) ||
            (lua_table == nullptr)||
            (lua_table->empty()))
        {
            DataApi::developer_error("Invalid Option!!  Missing either the Snort Option"
                " or the corresponding lua table!!");
            return false;
        }

        table_api.open_table(*lua_table);
        bool retval;

        // if the two names are not equal ...
        if ((lua_option != nullptr) && *snort_option != *lua_option)
        {
            retval = parse_int_option(*lua_option, stream, false);
            table_api.add_diff_option_comment("config " + *snort_option + ":", *lua_option);
        }
        else
        {
            retval = parse_int_option(*snort_option, stream, false);
        }

        table_api.close_table();
        stream.setstate(std::ios::eofbit); // not interested in any additional arguments
        return retval;
    }

private:
    const std::string* snort_option;
    const std::string* lua_table;
    const std::string* lua_option;
};

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option = nullptr>
static ConversionState* config_int_ctor(Converter& c)
{
    return new ConfigIntOption(c, snort_option, lua_table, lua_option);
}
} // namespace

/*************************************************
 *********************  asn1  ********************
 *************************************************/

static const std::string asn1 = "asn1";
static const ConvertMap asn1_api =
{
    asn1,
    config_int_ctor<& asn1, & detection>,
};

const ConvertMap* asn1_map = &asn1_api;

/*************************************************
 *************  max_attribute_hosts  *************
 *************************************************/

static const std::string max_attribute_hosts = "max_attribute_hosts";
static const std::string max_hosts = "max_hosts";
static const ConvertMap max_attribute_hosts_api =
{
    max_attribute_hosts,
    config_int_ctor<& max_attribute_hosts, & attribute_table, & max_hosts>,
};

const ConvertMap* max_attribute_hosts_map = &max_attribute_hosts_api;

/*************************************************
 *******  max_attribute_services_per_host  *******
 *************************************************/

static const std::string max_attribute_services_per_host = "max_attribute_services_per_host";
static const std::string max_services_per_host = "max_services_per_host";
static const ConvertMap max_attribute_services_per_host_api =
{
    max_attribute_services_per_host,
    config_int_ctor<& max_attribute_services_per_host, & attribute_table, & max_services_per_host>,
};

const ConvertMap* max_attribute_services_per_host_map = &max_attribute_services_per_host_api;

/*************************************************
 *************  max_ip6_extensions  **************
 *************************************************/

static const std::string max_ip6_extensions = "max_ip6_extensions";
static const ConvertMap max_ip6_extensions_api =
{
    max_ip6_extensions,
    config_int_ctor<& max_ip6_extensions, & network>,
};

const ConvertMap* max_ip6_extensions_map = &max_ip6_extensions_api;

/*************************************************
 *************  max_attribute_hosts  *************
 *************************************************/

static const std::string max_metadata_services = "max_metadata_services";
static const ConvertMap max_metadata_services_api =
{
    max_metadata_services,
    config_int_ctor<& max_metadata_services, & attribute_table>,
};

const ConvertMap* max_metadata_services_map = &max_metadata_services_api;

/*************************************************
 ***********  max_mpls_labelchain_len  ***********
 *************************************************/

static const std::string max_mpls_labelchain_len = "max_mpls_labelchain_len";
static const std::string max_mpls_stack_depth = "max_mpls_stack_depth";
static const ConvertMap max_mpls_labelchain_len_api =
{
    max_mpls_labelchain_len,
    config_int_ctor<& max_mpls_labelchain_len,
    & mpls,
    & max_mpls_stack_depth>,
};

const ConvertMap* max_mpls_labelchain_len_map = &max_mpls_labelchain_len_api;

/*************************************************
 *******************  min_ttl  *******************
 *************************************************/

static const std::string min_ttl = "min_ttl";
static const ConvertMap min_ttl_api =
{
    min_ttl,
    config_int_ctor<& min_ttl, & network>,
};

const ConvertMap* min_ttl_map = &min_ttl_api;

/*************************************************
 *******************  new_ttl  *******************
 *************************************************/

static const std::string new_ttl = "new_ttl";
static const ConvertMap new_ttl_api =
{
    new_ttl,
    config_int_ctor<& new_ttl, & network>,
};

const ConvertMap* new_ttl_map = &new_ttl_api;

/*************************************************
 **************  pcre_match_limit   **************
 *************************************************/

static const std::string pcre_match_limit = "pcre_match_limit";
static const ConvertMap pcre_match_limit_api =
{
    pcre_match_limit,
    config_int_ctor<& pcre_match_limit, & detection>,
};

const ConvertMap* pcre_match_limit_map = &pcre_match_limit_api;

/**************************************************
 **********  pcre_match_limit_recursion  **********
 **************************************************/

static const std::string pcre_match_limit_recursion = "pcre_match_limit_recursion";
static const ConvertMap pcre_match_limit_recursion_api =
{
    pcre_match_limit_recursion,
    config_int_ctor<& pcre_match_limit_recursion, & detection>,
};

const ConvertMap* pcre_match_limit_recursion_map = &pcre_match_limit_recursion_api;

/*************************************************
 ******************  pkt_count   *****************
 *************************************************/

static const std::string pkt_count = "pkt_count";
static const std::string limit = "limit";
static const ConvertMap pkt_count_api =
{
    pkt_count,
    config_int_ctor<& pkt_count, & packets, & limit>,
};

const ConvertMap* pkt_count_map = &pkt_count_api;

/**************************************************
 ******************** snaplen  ********************
 **************************************************/

static const std::string snaplen = "snaplen";
static const ConvertMap snaplen_api =
{
    snaplen,
    config_int_ctor<& snaplen, & daq>,
};

const ConvertMap* snaplen_map = &snaplen_api;

/**************************************************
 ************** tagged_packet_limit  **************
 **************************************************/

static const std::string tagged_packet_limit = "tagged_packet_limit";
static const ConvertMap tagged_packet_limit_api =
{
    tagged_packet_limit,
    config_int_ctor<& tagged_packet_limit, & output>,
};

const ConvertMap* tagged_packet_limit_map = &tagged_packet_limit_api;
} // namespace config

