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
// kws_rule.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "conversion_state.h"

namespace keywords
{
namespace
{
class RuleHeader : public ConversionState
{
public:
    explicit RuleHeader(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
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
        rule_api.add_hdr_data(hdr_data);
    }

    // Now, remove the last ')' and anything beyond. We will automatically
    // add that part back when printing each rule.
    const std::istringstream::off_type curr_pos = data_stream.tellg();
    std::string rule_string = data_stream.str();
    std::size_t end_pos = rule_string.rfind(')');
    rule_string = rule_string.substr(0, end_pos);
    util::rtrim(rule_string); // guarantee last char is a rule opt/subopt
    data_stream.str(rule_string);
    data_stream.seekg(curr_pos);  // position was reset. so find curr position

    // and call the first keywords
    return set_next_rule_state(data_stream);
}

/********************************
 *******  GENERAL API ***********
 ********************************/

template<const std::string* name>
static ConversionState* rule_ctor(Converter& c)
{
    c.get_rule_api().add_hdr_data(*name);
    return new RuleHeader(c);
}

template<const std::string* name>
static ConversionState* dep_rule_ctor(Converter& c)
{
    c.get_rule_api().add_hdr_data(*name);
    c.get_rule_api().make_rule_a_comment();
    c.get_rule_api().add_comment("The '" + *name + "' ruletype is no longer supported");
    return new RuleHeader(c);
}

template<const std::string* name, const std::string* old>
static ConversionState* conv_rule_ctor(Converter& c)
{
    c.get_rule_api().add_hdr_data(*name);
    c.get_rule_api().add_comment(
        "The '" + *old + "' ruletype is no longer supported, using " + *name);
    return new RuleHeader(c);
}

static ConversionState* drop_rule_ctor(Converter& c)
{
    c.get_rule_api().add_hdr_data("block");
    c.get_rule_api().add_comment(
        "Ruletype 'drop' discards the current packet only; "
        "using 'block' to discard all packets on flow");
    return new RuleHeader(c);
}

static const std::string alert = "alert";
static const std::string c_alert = "# alert";
static const std::string block = "block";
static const std::string log = "log";
static const std::string pass = "pass";
static const std::string drop = "drop";
static const std::string reject = "reject";

static const std::string sblock = "sblock";
static const std::string sdrop = "sdrop";

static const std::string activate = "activate";
static const std::string dynamic = "dynamic";

static const ConvertMap alert_api = { alert, rule_ctor<& alert>};
static const ConvertMap c_alert_api = { c_alert, rule_ctor<& c_alert>};
static const ConvertMap block_api = { block, rule_ctor<& block>};
static const ConvertMap log_api = { log, rule_ctor<& log>};
static const ConvertMap pass_api = { pass, rule_ctor<& pass>};
static const ConvertMap drop_api = { drop, drop_rule_ctor};
static const ConvertMap reject_api = { reject, rule_ctor<& reject>};

static const ConvertMap sblock_api = { sblock, conv_rule_ctor<& block, &sblock>};
static const ConvertMap sdrop_api = { sdrop, conv_rule_ctor<& block, &sdrop>};

static const ConvertMap activate_api = { activate, dep_rule_ctor<& activate>};
static const ConvertMap dynamic_api = { dynamic, dep_rule_ctor<& dynamic>};

const ConvertMap* alert_map = &alert_api;
const ConvertMap* c_alert_map = &c_alert_api;
const ConvertMap* block_map = &block_api;
const ConvertMap* log_map = &log_api;
const ConvertMap* pass_map = &pass_api;
const ConvertMap* drop_map = &drop_api;
const ConvertMap* reject_map = &reject_api;

const ConvertMap* sblock_map = &sblock_api;
const ConvertMap* sdrop_map = &sdrop_api;

const ConvertMap* activate_map = &activate_api;
const ConvertMap* dynamic_map = &dynamic_api;

} // namespace keywords

