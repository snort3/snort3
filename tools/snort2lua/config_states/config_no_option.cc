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
// config_no_options.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class DeadCode : public ConversionState
{
public:
    DeadCode(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override
    {
        data_stream.setstate(std::ios::eofbit); // these deleted, not failures
        return true;
    }
};

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option>
static ConversionState* config_true_no_opt_ctor(Converter& c)
{
    c.get_table_api().open_table(*lua_table);

    if (*snort_option != *lua_option)
    {
        c.get_table_api().add_diff_option_comment(
            "config " + *snort_option + ":", *lua_option);
    }

    c.get_table_api().add_option(*lua_option, true);
    c.get_table_api().close_table();
    return new DeadCode(c);
}

template<const std::string* snort_option,
const std::string* lua_table>
static ConversionState* config_true_no_opt_ctor(Converter& c)
{
    c.get_table_api().open_table(*lua_table);
    c.get_table_api().add_option(*snort_option, true);
    c.get_table_api().close_table();
    return new DeadCode(c);
}

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option>
static ConversionState* config_false_no_opt_ctor(Converter& c)
{
    c.get_table_api().open_table(*lua_table);

    // WARNING:  THIS WILL SEGFAULT if any variable is nullptr!!
    if (*snort_option != *lua_option)
        c.get_table_api().add_diff_option_comment("config " + *snort_option + ":", *lua_option);

    c.get_table_api().add_option(*lua_option, false);
    c.get_table_api().close_table();
    return new DeadCode(c);
}

#if 0
// currently unused - for future reference
template<const std::string* snort_option,
const std::string* lua_table>
static ConversionState* config_false_no_opt_ctor(Converter& c)
{
    c.get_table_api().open_table(*lua_table);
    c.get_table_api().add_option(*snort_option, false);
    c.get_table_api().close_table();
    return new DeadCode(c);
}
#endif
} // namespace

/*************************************************
 ****************  STRUCT_NAMES  *****************
 *************************************************/

static const std::string alerts = "alerts";
static const std::string udp = "udp";
static const std::string mpls = "mpls";
static const std::string daq = "daq";
static const std::string detection = "detection";
static const std::string ips = "ips";
static const std::string packets = "packets";
static const std::string process = "process";
static const std::string output = "output";
static const std::string rewrite = "rewrite";

/*************************************************
 **********  addressspace_agnostic  **********
 *************************************************/

static const std::string addressspace_agnostic = "addressspace_agnostic";
static const std::string address_space_agnostic = "address_space_agnostic";
static const ConvertMap addressspace_agnostic_api =
{
    addressspace_agnostic,
    config_true_no_opt_ctor<& addressspace_agnostic, & packets, & address_space_agnostic>,
};

const ConvertMap* addressspace_agnostic_map = &addressspace_agnostic_api;

/*************************************************
 **********  alert_with_interface_name  **********
 *************************************************/

static const std::string alert_with_interface_name = "alert_with_interface_name";
static const ConvertMap alert_with_interface_name_api =
{
    alert_with_interface_name,
    config_true_no_opt_ctor<& alert_with_interface_name, & alerts>,
};

const ConvertMap* alert_with_interface_name_map = &alert_with_interface_name_api;

/*************************************************
 *********  autogenerate Decoder Rules ***********
 *************************************************/

static const std::string autogenerate_preprocessor_decoder_rules =
    "autogenerate_preprocessor_decoder_rules";
static const std::string enable_builtin_rules = "enable_builtin_rules";
static const ConvertMap autogenerate_decode_rules_api =
{
    autogenerate_preprocessor_decoder_rules,
    config_true_no_opt_ctor<& autogenerate_preprocessor_decoder_rules, & ips,
    & enable_builtin_rules>
};

const ConvertMap* autogenerate_preprocessor_decoder_rules_map = &autogenerate_decode_rules_api;

/*************************************************
 *************  daemon  ****************
 *************************************************/

static const std::string daemon = "daemon";
static const ConvertMap daemon_api =
{
    daemon,
    config_true_no_opt_ctor<& daemon, & process>,
};

const ConvertMap* daemon_map = &daemon_api;

/*************************************************
 *****************  dirty_pig  *******************
 *************************************************/

static const std::string dirty_pig = "dirty_pig";
static const ConvertMap dirty_pig_api =
{
    dirty_pig,
    config_true_no_opt_ctor<& dirty_pig, & process>,
};

const ConvertMap* dirty_pig_map = &dirty_pig_api;

/*************************************************
 *****  disable rewrite rules with replace *******
 *************************************************/

static const std::string disable_replace = "disable_replace";
static const ConvertMap disable_replace_api =
{
    disable_replace,
    config_true_no_opt_ctor<& disable_replace, & rewrite>,
};

const ConvertMap* disable_replace_map = &disable_replace_api;

/*************************************************
 ***************  dump_chars_only  ***************
 *************************************************/

static const std::string dump_chars_only = "dump_chars_only";
static const ConvertMap dump_chars_only_api =
{
    dump_chars_only,
    config_true_no_opt_ctor<& dump_chars_only, & output>,
};

const ConvertMap* dump_chars_only_map = &dump_chars_only_api;

/*************************************************
 *****************  dump_payload  ****************
 *************************************************/

static const std::string dump_payload = "dump_payload";
static const ConvertMap dump_payload_api =
{
    dump_payload,
    config_true_no_opt_ctor<& dump_payload, & output>,
};

const ConvertMap* dump_payload_map = &dump_payload_api;

/*************************************************
 ************  dump_payload_verbose  *************
 *************************************************/

static const std::string dump_payload_verbose = "dump_payload_verbose";
static const ConvertMap dump_payload_verbose_api =
{
    dump_payload_verbose,
    config_true_no_opt_ctor<& dump_payload_verbose, & output>,
};

const ConvertMap* dump_payload_verbose_map = &dump_payload_verbose_api;

/*************************************************
 ************  enable_mpls_multicast  ************
 *************************************************/

static const std::string enable_mpls_multicast = "enable_mpls_multicast";
static const ConvertMap enable_mpls_multicast_api =
{
    enable_mpls_multicast,
    config_true_no_opt_ctor<& enable_mpls_multicast, & mpls>
};

const ConvertMap* enable_mpls_multicast_map = &enable_mpls_multicast_api;

/*************************************************
 ********  enable_deep_teredo_inspection  ********
 *************************************************/

static const std::string enable_deep_teredo_inspection =
    "enable_deep_teredo_inspection";
static const std::string deep_teredo_inspection =
    "deep_teredo_inspection";
static const ConvertMap enable_deep_teredo_inspection_api =
{
    enable_deep_teredo_inspection,
    config_true_no_opt_ctor<& enable_deep_teredo_inspection, & udp, & deep_teredo_inspection>
};

const ConvertMap* enable_deep_teredo_inspection_map = &enable_deep_teredo_inspection_api;

/*************************************************
 ******************  enable_gtp ******************
 *************************************************/

static const std::string enable_gtp = "enable_gtp";
static const ConvertMap enable_gtp_api =
{
    enable_gtp,
    config_true_no_opt_ctor<& enable_gtp, & udp>
};

const ConvertMap* enable_gtp_map = &enable_gtp_api;

/*************************************************
 **********  enable_mpls_overlapping_ip **********
 *************************************************/

static const std::string enable_mpls_overlapping_ip = "enable_mpls_overlapping_ip";
static const ConvertMap enable_mpls_overlapping_ip_api =
{
    enable_mpls_overlapping_ip,
    config_true_no_opt_ctor<& enable_mpls_overlapping_ip, & mpls>
};

const ConvertMap* enable_mpls_overlapping_ip_map = &enable_mpls_overlapping_ip_api;

/*************************************************
 ********************  nopcre  *******************
 *************************************************/

static const std::string nopcre = "nopcre";
static const std::string pcre_enable = "pcre_enable";
static const ConvertMap nopcre_api =
{
    nopcre,
    config_false_no_opt_ctor<& nopcre, & detection, & pcre_enable>
};

const ConvertMap* nopcre_map = &nopcre_api;

/*************************************************
 ******************  no_promisc  *****************
 *************************************************/

static const std::string no_promisc = "no_promisc";
static const ConvertMap no_promisc_api =
{
    no_promisc,
    config_true_no_opt_ctor<& no_promisc, & daq>
};

const ConvertMap* no_promisc_map = &no_promisc_api;

/*************************************************
 ******************  obfuscate  ******************
 *************************************************/

static const std::string obfuscate = "obfuscate";
static const ConvertMap obfuscate_api =
{
    obfuscate,
    config_true_no_opt_ctor<& obfuscate, & output>
};

const ConvertMap* obfuscate_map = &obfuscate_api;

/*************************************************
 ********************  quiet  ********************
 *************************************************/

static const std::string quiet = "quiet";
static const ConvertMap quiet_api =
{
    quiet,
    config_true_no_opt_ctor<& quiet, & output>
};

const ConvertMap* quiet_map = &quiet_api;

/*************************************************
 ******************  show_year  ******************
 *************************************************/

static const std::string show_year = "show_year";
static const ConvertMap show_year_api =
{
    show_year,
    config_true_no_opt_ctor<& show_year, & output>
};

const ConvertMap* show_year_map = &show_year_api;

/*************************************************
 *******************  stateful  ******************
 *************************************************/

static const std::string stateful = "stateful";
static const ConvertMap stateful_api =
{
    stateful,
    config_true_no_opt_ctor<& stateful, & alerts>
};

const ConvertMap* stateful_map = &stateful_api;

/*************************************************
 *********************  utc  *********************
 *************************************************/

static const std::string utc = "utc";
static const ConvertMap utc_api =
{
    utc,
    config_true_no_opt_ctor<& utc, & process>,
};

const ConvertMap* utc_map = &utc_api;

/*************************************************
 ***************  verbose  ***************
 *************************************************/

static const std::string verbose = "verbose";
static const ConvertMap verbose_api =
{
    verbose,
    config_true_no_opt_ctor<& verbose, & output>,
};

const ConvertMap* verbose_map = &verbose_api;

/*************************************************
 ****************  vlan_agnostic  ****************
 *************************************************/

static const std::string vlan_agnostic = "vlan_agnostic";
static const ConvertMap vlan_agnostic_api =
{
    vlan_agnostic,
    config_true_no_opt_ctor<& vlan_agnostic, & packets>,
};

const ConvertMap* vlan_agnostic_map = &vlan_agnostic_api;
} // namespace config

