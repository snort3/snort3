//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_gid_sid.cc author Maya Dagon <mdagon@cisco.com>

//
// Handle special case of deprecated gid 120:
// Rules were moved to gid 119, with sids starting from 35.
//
// In case the rule is using gid 120 - convert it to gid 119 and update
// sid.
// Handle 2 cases: sid was read before/after gid.

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Gid : public ConversionState
{
public:
    Gid(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};

class Sid : public ConversionState
{
public:
    Sid(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
    static void convert_sid(std::string& sid, std::istringstream& data, RuleApi& rule_api);
};
} // namespace

//
// Gid
//

bool Gid::convert(std::istringstream& data_stream)
{
    std::string gid = util::get_rule_option_args(data_stream);

    const std::string old_http_gid("120");  
    if (gid.compare(old_http_gid) == 0)
    {
        const std::string nhi_gid("119");
        gid.assign(nhi_gid);
        rule_api.old_http_rule();

        // Update sid
        std::string sid = rule_api.get_option("sid");
        if (!sid.empty())
        {
            Sid::convert_sid(sid, data_stream, rule_api);
            rule_api.update_option("sid", sid);
        }
    }
    rule_api.add_option("gid", gid);
    return set_next_rule_state(data_stream);
}

//
// Sid
//

void Sid::convert_sid(std::string& sid, std::istringstream& data_stream, RuleApi& rule_api)
{
    int sid_num;
    try
    {
        sid_num = std::stoi(sid);
    }
    catch (...)
    {
        rule_api.bad_rule(data_stream, "sid - invalid input, expecting int type");
        return;
    }
    const int sid_offset = 100;
    sid.assign(std::to_string(sid_num + sid_offset));
}

bool Sid::convert(std::istringstream& data_stream)
{
    std::string sid = util::get_rule_option_args(data_stream);

    if (rule_api.is_old_http_rule())
        convert_sid(sid, data_stream, rule_api);

    rule_api.add_option("sid", sid);
    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Gid(c); }

static const ConvertMap rule_gid =
{
    "gid",
    ctor,
};

const ConvertMap* gid_map = &rule_gid;

static ConversionState* sid_ctor(Converter& c)
{ return new Sid(c); }

static const ConvertMap rule_sid =
{
    "sid",
    sid_ctor,
};

const ConvertMap* sid_map = &rule_sid;
} // namespace rules

