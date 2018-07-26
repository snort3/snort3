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
// config_deleted.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Deleted : public ConversionState
{
public:
    Deleted(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Deleted::convert(std::istringstream& data_stream)
{
    data_stream.setstate(std::ios::eofbit); // deleted, not failures
    return true;
}

template<const std::string* snort_option>
static ConversionState* deleted_ctor(Converter& c)
{
    // set here since not all deleted configs have options
    if (!DataApi::is_quiet_mode())
    {
        c.get_table_api().open_table("deleted_snort_config_options");
        c.get_table_api().add_deleted_comment("config " + *snort_option + "[:.*]");
        c.get_table_api().close_table();
    }

    return new Deleted(c);
}

/*************************************************
 ********************  cs_dir  *******************
 *************************************************/

static const std::string cs_dir = "cs_dir";
static const ConvertMap cs_dir_api =
{
    cs_dir,
    deleted_ctor<& cs_dir>,
};

const ConvertMap* cs_dir_map = &cs_dir_api;

/*************************************************
 *******  disable-attribute-reload-thread  *******
 *************************************************/

static const std::string disable_attribute_reload_thread = "disable-attribute-reload-thread";
static const ConvertMap disable_attribute_reload_thread_api =
{
    disable_attribute_reload_thread,
    deleted_ctor<& disable_attribute_reload_thread>,
};

const ConvertMap* disable_attribute_reload_thread_map = &disable_attribute_reload_thread_api;

/*************************************************
 ************  disable_decode_alerts  ************
 *************************************************/

static const std::string disable_decode_alerts = "disable_decode_alerts";
static const ConvertMap disable_decode_alerts_api =
{
    disable_decode_alerts,
    deleted_ctor<& disable_decode_alerts>,
};

const ConvertMap* disable_decode_alerts_map = &disable_decode_alerts_api;

/*************************************************
 *************  disable_decode_drops *************
 *************************************************/

static const std::string disable_decode_drops = "disable_decode_drops";
static const ConvertMap disable_decode_drops_api =
{
    disable_decode_drops,
    deleted_ctor<& disable_decode_drops>,
};

const ConvertMap* disable_decode_drops_map = &disable_decode_drops_api;

/*************************************************
 *************  disable_ipopt_alerts  ************
 *************************************************/

static const std::string disable_ipopt_alerts = "disable_ipopt_alerts";
static const ConvertMap disable_ipopt_alerts_api =
{
    disable_ipopt_alerts,
    deleted_ctor<& disable_ipopt_alerts>,
};

const ConvertMap* disable_ipopt_alerts_map = &disable_ipopt_alerts_api;

/*************************************************
 *************  disable_ipopt_drops  *************
 *************************************************/

static const std::string disable_ipopt_drops = "disable_ipopt_drops";
static const ConvertMap disable_ipopt_drops_api =
{
    disable_ipopt_drops,
    deleted_ctor<& disable_ipopt_drops>,
};

const ConvertMap* disable_ipopt_drops_map = &disable_ipopt_drops_api;

/*************************************************
 ************  disable_tcpopt_alerts  ************
 *************************************************/

static const std::string disable_tcpopt_alerts = "disable_tcpopt_alerts";
static const ConvertMap disable_tcpopt_alerts_api =
{
    disable_tcpopt_alerts,
    deleted_ctor<& disable_tcpopt_alerts>,
};

const ConvertMap* disable_tcpopt_alerts_map = &disable_tcpopt_alerts_api;

/*************************************************
 *************  disable_tcpopt_drops  ************
 *************************************************/

static const std::string disable_tcpopt_drops = "disable_tcpopt_drops";
static const ConvertMap disable_tcpopt_drops_api =
{
    disable_tcpopt_drops,
    deleted_ctor<& disable_tcpopt_drops>,
};

const ConvertMap* disable_tcpopt_drops_map = &disable_tcpopt_drops_api;

/*************************************************
 ******  disable_tcpopt_experimental_alerts  *****
 *************************************************/

static const std::string disable_tcpopt_experimental_alerts = "disable_tcpopt_experimental_alerts";
static const ConvertMap disable_tcpopt_experimental_alerts_api =
{
    disable_tcpopt_experimental_alerts,
    deleted_ctor<& disable_tcpopt_experimental_alerts>,
};

const ConvertMap* disable_tcpopt_experimental_alerts_map = &disable_tcpopt_experimental_alerts_api;

/*************************************************
 *******  disable_tcpopt_experimental_drops ******
 *************************************************/

static const std::string disable_tcpopt_experimental_drops = "disable_tcpopt_experimental_drops";
static const ConvertMap disable_tcpopt_experimental_drops_api =
{
    disable_tcpopt_experimental_drops,
    deleted_ctor<& disable_tcpopt_experimental_drops>,
};

const ConvertMap* disable_tcpopt_experimental_drops_map = &disable_tcpopt_experimental_drops_api;

/*************************************************
 ********  disable_tcpopt_obsolete_alerts  *******
 *************************************************/

static const std::string disable_tcpopt_obsolete_alerts = "disable_tcpopt_obsolete_alerts";
static const ConvertMap disable_tcpopt_obsolete_alerts_api =
{
    disable_tcpopt_obsolete_alerts,
    deleted_ctor<& disable_tcpopt_obsolete_alerts>,
};

const ConvertMap* disable_tcpopt_obsolete_alerts_map = &disable_tcpopt_obsolete_alerts_api;

/*************************************************
 *********  disable_tcpopt_obsolete_drops  ********
 *************************************************/

static const std::string disable_tcpopt_obsolete_drops = "disable_tcpopt_obsolete_drops";
static const ConvertMap disable_tcpopt_obsolete_drops_api =
{
    disable_tcpopt_obsolete_drops,
    deleted_ctor<& disable_tcpopt_obsolete_drops>,
};

const ConvertMap* disable_tcpopt_obsolete_drops_map = &disable_tcpopt_obsolete_drops_api;

/*************************************************
 **********  disable_tcpopt_ttcp_alerts  **********
 *************************************************/

static const std::string disable_tcpopt_ttcp_alerts = "disable_tcpopt_ttcp_alerts";
static const ConvertMap disable_tcpopt_ttcp_alerts_api =
{
    disable_tcpopt_ttcp_alerts,
    deleted_ctor<& disable_tcpopt_ttcp_alerts>,
};

const ConvertMap* disable_tcpopt_ttcp_alerts_map = &disable_tcpopt_ttcp_alerts_api;

/*************************************************
 **************  disable_ttcp_drops  **************
 *************************************************/

static const std::string disable_ttcp_drops = "disable_ttcp_drops";
static const ConvertMap disable_ttcp_drops_api =
{
    disable_ttcp_drops,
    deleted_ctor<& disable_ttcp_drops>,
};

const ConvertMap* disable_ttcp_drops_map = &disable_ttcp_drops_api;

/*************************************************
 ************  dump-dynamic-rules-path  ***********
 *************************************************/

static const std::string dump_dynamic_rules_path = "dump-dynamic-rules-path";
static const ConvertMap dump_dynamic_rules_path_api =
{
    dump_dynamic_rules_path,
    deleted_ctor<& dump_dynamic_rules_path>,
};

const ConvertMap* dump_dynamic_rules_path_map = &dump_dynamic_rules_path_api;

/*************************************************
 *************  enable_decode_drops  *************
 *************************************************/

static const std::string enable_decode_drops = "enable_decode_drops";
static const ConvertMap enable_decode_drops_api =
{
    enable_decode_drops,
    deleted_ctor<& enable_decode_drops>,
};

const ConvertMap* enable_decode_drops_map = &enable_decode_drops_api;

/*************************************************
 *************  disable_ttcp_alerts  *************
 *************************************************/

static const std::string disable_ttcp_alerts = "disable_ttcp_alerts";
static const ConvertMap disable_ttcp_alerts_api =
{
    disable_ttcp_alerts,
    deleted_ctor<& disable_ttcp_alerts>,
};

const ConvertMap* disable_ttcp_alerts_map = &disable_ttcp_alerts_api;

/*************************************************
 ********  enable_decode_oversized_alerts  *******
 *************************************************/

static const std::string enable_decode_oversized_alerts = "enable_decode_oversized_alerts";
static const ConvertMap enable_decode_oversized_alerts_api =
{
    enable_decode_oversized_alerts,
    deleted_ctor<& enable_decode_oversized_alerts>,
};

const ConvertMap* enable_decode_oversized_alerts_map = &enable_decode_oversized_alerts_api;

/*************************************************
 ********  enable_decode_oversized_drops  ********
 *************************************************/

static const std::string enable_decode_oversized_drops = "enable_decode_oversized_drops";
static const ConvertMap enable_decode_oversized_drops_api =
{
    enable_decode_oversized_drops,
    deleted_ctor<& enable_decode_oversized_drops>,
};

const ConvertMap* enable_decode_oversized_drops_map = &enable_decode_oversized_drops_api;

/*************************************************
 **************  enable_ipopt_drops  *************
 *************************************************/

static const std::string enable_ipopt_drops = "enable_ipopt_drops";
static const ConvertMap enable_ipopt_drops_api =
{
    enable_ipopt_drops,
    deleted_ctor<& enable_ipopt_drops>,
};

const ConvertMap* enable_ipopt_drops_map = &enable_ipopt_drops_api;

/*************************************************
 *************  enable_tcpopt_drops  *************
 *************************************************/

static const std::string enable_tcpopt_drops = "enable_tcpopt_drops";
static const ConvertMap enable_tcpopt_drops_api =
{
    enable_tcpopt_drops,
    deleted_ctor<& enable_tcpopt_drops>,
};

const ConvertMap* enable_tcpopt_drops_map = &enable_tcpopt_drops_api;

/*************************************************
 *******  enable_tcpopt_experimental_drops  ******
 *************************************************/

static const std::string enable_tcpopt_experimental_drops = "enable_tcpopt_experimental_drops";
static const ConvertMap enable_tcpopt_experimental_drops_api =
{
    enable_tcpopt_experimental_drops,
    deleted_ctor<& enable_tcpopt_experimental_drops>,
};

const ConvertMap* enable_tcpopt_experimental_drops_map = &enable_tcpopt_experimental_drops_api;

/*************************************************
 *********  enable_tcpopt_obsolete_drops  ********
 *************************************************/

static const std::string enable_tcpopt_obsolete_drops = "enable_tcpopt_obsolete_drops";
static const ConvertMap enable_tcpopt_obsolete_drops_api =
{
    enable_tcpopt_obsolete_drops,
    deleted_ctor<& enable_tcpopt_obsolete_drops>,
};

const ConvertMap* enable_tcpopt_obsolete_drops_map = &enable_tcpopt_obsolete_drops_api;

/*************************************************
 ***********  enable_tcpopt_ttcp_drops  ***********
 *************************************************/

static const std::string enable_tcpopt_ttcp_drops = "enable_tcpopt_ttcp_drops";
static const ConvertMap enable_tcpopt_ttcp_drops_api =
{
    enable_tcpopt_ttcp_drops,
    deleted_ctor<& enable_tcpopt_ttcp_drops>,
};

const ConvertMap* enable_tcpopt_ttcp_drops_map = &enable_tcpopt_ttcp_drops_api;

/*************************************************
 ***********  enable_ttcp_drops  ***********
 *************************************************/

static const std::string enable_ttcp_drops = "enable_ttcp_drops";
static const ConvertMap enable_ttcp_drops_api =
{
    enable_ttcp_drops,
    deleted_ctor<& enable_ttcp_drops>,
};

const ConvertMap* enable_ttcp_drops_map = &enable_ttcp_drops_api;

/*************************************************
 *************  log_ipv6_extra_data  *************
 *************************************************/

static const std::string log_ipv6_extra_data = "log_ipv6_extra_data";
static const ConvertMap log_ipv6_extra_data_api =
{
    log_ipv6_extra_data,
    deleted_ctor<& log_ipv6_extra_data>
};

const ConvertMap* log_ipv6_extra_data_map = &log_ipv6_extra_data_api;


/*************************************************
 ***********  nolog***********
 *************************************************/

static const std::string nolog = "nolog";
static const ConvertMap nolog_api =
{
    nolog,
    deleted_ctor<& nolog>,
};

const ConvertMap* nolog_map = &nolog_api;


/*************************************************
 **************  flexresp2_attempts  *************
 *************************************************/

static const std::string flexresp2_attempts = "flexresp2_attempts";
static const ConvertMap flexresp2_attempts_api =
{
    flexresp2_attempts,
    deleted_ctor<& flexresp2_attempts>,
};

const ConvertMap* flexresp2_attempts_map = &flexresp2_attempts_api;

/*************************************************
 *************  flexresp2_interface  *************
 *************************************************/

static const std::string flexresp2_interface = "flexresp2_interface";
static const ConvertMap flexresp2_interface_api =
{
    flexresp2_interface,
    deleted_ctor<& flexresp2_interface>,
};
const ConvertMap* flexresp2_interface_map = &flexresp2_interface_api;

/*************************************************
 ***************  flexresp2_memcap  **************
 *************************************************/

static const std::string flexresp2_memcap = "flexresp2_memcap";
static const ConvertMap flexresp2_memcap_api =
{
    flexresp2_memcap,
    deleted_ctor<& flexresp2_memcap>,
};
const ConvertMap* flexresp2_memcap_map = &flexresp2_memcap_api;

/*************************************************
 ****************  flexresp2_rows  ***************
 *************************************************/

static const std::string flexresp2_rows = "flexresp2_rows";
static const ConvertMap flexresp2_rows_api =
{
    flexresp2_rows,
    deleted_ctor<& flexresp2_rows>,
};
const ConvertMap* flexresp2_rows_map = &flexresp2_rows_api;

/*************************************************
 ****************  flowbits_size  ****************
 *************************************************/

static const std::string flowbits_size = "flowbits_size";
static const ConvertMap flowbits_size_api =
{
    flowbits_size,
    deleted_ctor<& flowbits_size>,
};

const ConvertMap* flowbits_size_map = &flowbits_size_api;

/*************************************************
 ************  include_vlan_in_alerts  ***********
 *************************************************/

static const std::string include_vlan_in_alerts = "include_vlan_in_alerts";
static const ConvertMap include_vlan_in_alerts_api =
{
    include_vlan_in_alerts,
    deleted_ctor<& include_vlan_in_alerts>,
};
const ConvertMap* include_vlan_in_alerts_map = &include_vlan_in_alerts_api;

/*************************************************
 ******************  interface  ******************
 *************************************************/

static const std::string interface = "interface";
static const ConvertMap interface_api =
{
    interface,
    deleted_ctor<& interface>,
};
const ConvertMap* interface_map = &interface_api;

/*************************************************
 *****************  layer2resets  ****************
 *************************************************/

static const std::string layer2resets = "layer2resets";
static const ConvertMap layer2resets_api =
{
    layer2resets,
    deleted_ctor<& layer2resets>,
};
const ConvertMap* layer2resets_map = &layer2resets_api;

/*************************************************
 ****************  so_rule_memcap  ***************
 *************************************************/

static const std::string so_rule_memcap = "so_rule_memcap";
static const ConvertMap so_rule_memcap_api =
{
    so_rule_memcap,
    deleted_ctor<& so_rule_memcap>,
};
const ConvertMap* so_rule_memcap_map = &so_rule_memcap_api;

/*************************************************
 *****************  disable_inline_init_failopen  *******************
 *************************************************/

static const std::string disable_inline_init_failopen = "disable_inline_init_failopen";
static const ConvertMap disable_inline_init_failopen_api =
{
    disable_inline_init_failopen,
    deleted_ctor<& disable_inline_init_failopen>,
};

const ConvertMap* disable_inline_init_failopen_map = &disable_inline_init_failopen_api;

/*************************************************
 *****************  daq_mode  *******************
 *************************************************/

static const std::string daq_mode = "daq_mode";
static const ConvertMap daq_mode_api =
{
    daq_mode,
    deleted_ctor<& daq_mode>,
};

const ConvertMap* daq_mode_map = &daq_mode_api;

/*************************************************
 *************  decode_data_link  ****************
 *************************************************/

static const std::string decode_data_link = "decode_data_link";
static const ConvertMap decode_data_link_api =
{
    decode_data_link,
    deleted_ctor<& decode_data_link>,
};

const ConvertMap* decode_data_link_map = &decode_data_link_api;

/*************************************************
 *************  protected_content ****************
 *************************************************/

static const std::string protected_content = "protected_content";
static const ConvertMap protected_content_api =
{
    protected_content,
    deleted_ctor<& protected_content>,
};

const ConvertMap* protected_content_map = &protected_content_api;

/*************************************************
 *************  sidechannel ****************
 *************************************************/

// FIXIT-H: This is temporary and needs to be translated to an appropriate `side_channel = {}`

static const std::string sidechannel = "sidechannel";
static const ConvertMap sidechannel_api =
{
    sidechannel,
    deleted_ctor<& sidechannel>,
};

const ConvertMap* sidechannel_map = &sidechannel_api;

} // namespace config
