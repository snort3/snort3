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
// rule_metadata.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Metadata : public ConversionState
{
public:
    Metadata(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Metadata::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string tmp;
    std::string value;
    std::string soid_val;
    std::string service;

    bool add_opt = true;

    tmp = util::get_rule_option_args(data_stream);
    std::istringstream metadata_stream(util::trim(tmp));

    while (metadata_stream >> keyword)
    {
        value = std::string();

        while (metadata_stream >> tmp &&
            tmp.back() != ',')
        {
            if (!value.empty())
                value += ' ';
            value += tmp;
            tmp = std::string();
        }

        // tmp can be empty if we hit the end of stream
        if (!value.empty() && !tmp.empty())
            value += ' ';
        value += tmp;

        // won't end with comma if end of metadata string
        if (value.back() == ',')
            value.pop_back();

        if (keyword == "rule-flushing")
            rule_api.add_comment("metadata: rule-flushing - deprecated");

        else if (keyword == "soid")
            soid_val = value;  // add this after metadata to keep ordering

        else if (keyword == "service")
        {
            if ( service.length() )
                service += ", ";
            service += value;  // add this after metadata to keep ordering
        }
        else if (keyword == "engine")
        {
            rule_api.make_rule_a_comment();
            rule_api.add_comment("metadata: engine - deprecated");
        }
        else
        {
            if ( add_opt )
            {
                // this is to avoid empty metadata (ie "metadata;")
                rule_api.add_option("metadata");
                add_opt = false;
            }
            rule_api.add_suboption(keyword, value);
        }
    }

    if (!service.empty())
        rule_api.add_option("service", service);

    if (!soid_val.empty())
        rule_api.add_option("soid", soid_val);

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Metadata(c);
}

static const std::string metadata = "metadata";
static const ConvertMap metadata_api =
{
    metadata,
    ctor,
};

const ConvertMap* metadata_map = &metadata_api;
} // namespace rules

