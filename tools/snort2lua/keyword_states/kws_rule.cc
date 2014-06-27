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
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool RuleHeader::convert(std::istringstream& data_stream)
{
    std::string hdr_data;

    // should technically be either one or seven options, but I'm
    // not doing error checking here.
    std::getline(data_stream, hdr_data, '(');
    std::istringstream in(hdr_data);

    while (in >> hdr_data)
    {
        ld->add_hdr_data(hdr_data);
    }


    // Now, remove the last ')' and anything beyond. We will automatically
    // add that part back when printing each rule.
    int curr_pos = data_stream.tellg();
    std::string rule_string = data_stream.str();
    int end_pos = rule_string.rfind(')');
    rule_string = rule_string.substr(0, end_pos);
    data_stream.str(rule_string);
    data_stream.seekg(curr_pos);  // position was reset. so find curr position

    // and call the first keywords
    return set_next_rule_state(data_stream);
}

/********************************
 *******  GENERAL API ***********
 ********************************/

template<const std::string *name>
static ConversionState* rule_ctor(Converter* cv, LuaData* ld)
{
    ld->begin_rule();
    ld->add_hdr_data(*name);
    return new RuleHeader(cv, ld);
}

template<const std::string *name>
static ConversionState* dep_rule_ctor(Converter* cv, LuaData* ld)
{
    ld->begin_rule();
    ld->add_hdr_data(*name);
    return new RuleHeader(cv, ld);
}


static const std::string alert = "alert";
static const std::string log = "log";
static const std::string pass = "pass";
static const std::string drop = "drop";
static const std::string reject = "reject";
static const std::string sdrop = "sdrop";
static const std::string activate = "activate";
static const std::string dynamic = "dynamic";

static const ConvertMap alert_api = {alert, rule_ctor<&alert>};
static const ConvertMap log_api = {log, rule_ctor<&log>};
static const ConvertMap pass_api = {pass, rule_ctor<&pass>};
static const ConvertMap drop_api = {drop, rule_ctor<&drop>};
static const ConvertMap reject_api = {reject, rule_ctor<&reject>};
static const ConvertMap sdrop_api = {sdrop, rule_ctor<&sdrop>};
static const ConvertMap activate_api = {activate, dep_rule_ctor<&activate>};
static const ConvertMap dynamic_api = {dynamic, dep_rule_ctor<&dynamic>};


const ConvertMap* alert_map = &alert_api;
const ConvertMap* log_map = &log_api;
const ConvertMap* pass_map = &pass_api;
const ConvertMap* drop_map = &drop_api;
const ConvertMap* reject_map = &reject_api;
const ConvertMap* sdrop_map = &sdrop_api;
const ConvertMap* activate_map = &activate_api;
const ConvertMap* dynamic_map = &dynamic_api;

