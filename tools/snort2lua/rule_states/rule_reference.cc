//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// rule_reference.cc author Yehor Velykozhon <yvelykoz@cisco.com>

#include <string>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "rule_api.h"

namespace rules
{
namespace
{
class Reference : public ConversionState
{
public:
    Reference(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Reference::convert(std::istringstream& data_stream)
{
    std::string args = util::get_rule_option_args(data_stream);

    size_t separator_pos = args.find_first_of(',');

    if (separator_pos == args.npos)
    {
        rule_api.add_comment("Option \"reference\" requires 2 argument: <scheme>, <id>");
        rule_api.add_comment("Original value of \"reference\" option: " + args);
        return set_next_rule_state(data_stream);
    }

    bool separator_first_symbol = separator_pos == 0;
    bool separator_last_symbol = separator_pos == (args.size() - 1);

    if (separator_first_symbol or separator_last_symbol)
        rule_api.bad_rule(data_stream, "reference requires 2 non-empty arguments");
    else
        rule_api.add_option("reference", args);

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* reference_ctor(Converter& c)
{ return new Reference(c); }

static const ConvertMap rule_reference =
{
    "reference",
    reference_ctor,
};

const ConvertMap* reference_map = &rule_reference;
} // namespace rules

