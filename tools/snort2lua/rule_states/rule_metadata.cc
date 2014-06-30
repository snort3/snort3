/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// rule_metadata.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "rule_states/rule_api.h"
#include "util/util.h"

namespace rules
{

namespace {


class Metadata : public ConversionState
{
public:
    Metadata(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Metadata() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool Metadata::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string tmp;
    std::string value;
    std::string soid_val = std::string();
    bool retval = true;

    retval = ld->add_rule_option("metadata");
    ld->select_option("metadata");

    tmp = util::get_rule_option_args(data_stream);
    std::istringstream metadata_stream(util::trim(tmp));


    while(metadata_stream >> keyword)
    {
        bool tmpval = true;
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

        if (!keyword.compare("rule-flushing"))
            ld->add_comment_to_rule("metadata: rule-flushing - deprecated");

        else if (!keyword.compare("soid"))
            soid_val = value;  // add this after metadata to keep ordering

        else if (!keyword.compare("engine"))
        {
            ld->make_rule_a_comment();
            ld->add_comment_to_rule("metadata: engine - deprecated");
        }

        else
        {
            tmpval = ld->add_suboption(keyword, value, ' ');
        }

        if (retval)
            retval = tmpval;

    }

    if (!soid_val.empty())
        retval = ld->add_rule_option("soid", soid_val);

    ld->unselect_option();
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Metadata(cv, ld);
}

static const std::string metadata = "metadata";
static const ConvertMap metadata_api =
{
    metadata,
    ctor,
};

const ConvertMap* metadata_map = &metadata_api;

} // namespace rules
