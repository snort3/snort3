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
// kws_rule.cc author Josh Rosenbaum <jorosenba@cisco.com>


#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"
#include "rule_states/rule_api.h"

namespace
{

class RuleHeader : public ConversionState
{
public:
    explicit RuleHeader(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~RuleHeader() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace

bool RuleHeader::convert(std::stringstream& data_stream)
{
    std::string hdr_data;
    bool rule_test;

    ld->begin_rule();

    // should technically be either one or seven options, but I'm
    // not doing error checking here.
    while (data_stream >> hdr_data && hdr_data.front() != ('('))
    {
        ld->add_hdr_data(hdr_data);
    }

    if (!hdr_data.compare("("))
    {
        if(!(data_stream >> hdr_data))
            return false;
    }
    else
    {
        hdr_data.erase(hdr_data.begin());
    }

    if(hdr_data.back() == ':')
        hdr_data.pop_back();

    // now, lets get the next option and start parsing!
    const ConvertMap* map = util::find_map(rules::rule_api, hdr_data);
    if (map)
    {
        cv->set_state(map->ctor(cv, ld));
        return true;
    }

    return false;
}

/********************************
 *******  GENERAL API ***********
 ********************************/


static ConversionState* deprecate_rule_ctor(Converter* cv, LuaData* ld)
{
    return new RuleHeader(cv, ld);
}


static ConversionState* rule_ctor(Converter* cv, LuaData* ld)
{
    return new RuleHeader(cv, ld);
}

static const ConvertMap alert_api = {"alert", rule_ctor};
static const ConvertMap log_api = {"log", rule_ctor};
static const ConvertMap pass_api = {"pass", rule_ctor};
static const ConvertMap drop_api = {"drop", rule_ctor};
static const ConvertMap reject_api = {"reject", rule_ctor};
static const ConvertMap sdrop_api = {"sdrop", rule_ctor};
static const ConvertMap activate_api = {"activate", deprecate_rule_ctor};
static const ConvertMap dynamic_api = {"dynamic", deprecate_rule_ctor};


const ConvertMap* alert_map = &alert_api;
const ConvertMap* log_map = &log_api;
const ConvertMap* pass_map = &pass_api;
const ConvertMap* drop_map = &drop_api;
const ConvertMap* reject_map = &reject_api;
const ConvertMap* sdrop_map = &sdrop_api;
const ConvertMap* activate_map = &activate_api;
const ConvertMap* dynamic_map = &dynamic_api;

