//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_convert_comma_list.cc author Maya Dagon <mdagon@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
/*
 * Convert rule option from comma list to a space separated list in qoutes:
 * x,y,z to "x y z"
 */

template<const std::string* converted_option_name>
class CommaListRuleOption : public ConversionState
{
public:
    CommaListRuleOption(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& stream) override
    {
        std::string val = util::get_rule_option_args(stream);

        size_t start_pos = 0;
        while ((start_pos = val.find(',', start_pos)) != std::string::npos)
        {
            val.replace(start_pos, 1, " ");
            start_pos += 1;
        }
        val.insert(0,1,'"');
        val.insert(val.end(),1,'"');
        rule_api.add_option(*converted_option_name, val);

        return set_next_rule_state(stream);
    }
};

template<const std::string* converted_option_name>
static ConversionState* comma_list_conversion_ctor(Converter& c)
{
    return new CommaListRuleOption<converted_option_name>(c);
}

/************************************
 *********  DNP3 IND **************
 ************************************/
static const std::string dnp3_ind = "dnp3_ind";
static const ConvertMap dnp3_ind_api =
{
    dnp3_ind,
    comma_list_conversion_ctor<&dnp3_ind>,
};

const ConvertMap* dnp3_ind_map = &dnp3_ind_api;

/************************************
 *********  DCE OPNUM **************
 ************************************/
static const std::string dce_opnum = "dce_opnum";
static const ConvertMap dce_opnum_api =
{
    dce_opnum,
    comma_list_conversion_ctor<&dce_opnum>,
};

const ConvertMap* dce_opnum_map = &dce_opnum_api;

/************************************
 *********  APPID **************
 ************************************/
static const std::string appid = "appid";
static const std::string appids = "appids";
static const ConvertMap appid_api =
{
    appid,
    comma_list_conversion_ctor<&appids>,
};

const ConvertMap* appid_map = &appid_api;

} // namespace rules

