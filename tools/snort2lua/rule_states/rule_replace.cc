//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// rule_replace.cc author Oleksii Shumeiko <oshumeik@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "rule_api.h"

namespace rules
{
namespace
{
class Replace : public ConversionState
{
public:
    Replace(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& stream) override
    {
        std::string args = util::get_rule_option_args(stream);

        if (args.empty())
            rule_api.bad_rule(stream, "replace requires an argument");
        else
            rule_api.add_option("replace", args);

        return set_next_rule_state(stream);
    }
};
} // namespace


/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    const std::string& old_action = c.get_rule_api().get_rule_old_action();

    if (old_action == "drop"
        || old_action == "sdrop"
        || old_action == "block"
        || old_action == "sblock"
        || old_action == "reject"
        || old_action == "react")
    {
        c.get_rule_api().add_comment(
            "Keeping '" + old_action + "' action, "
            "'replace' option is ignored.");

        return new Replace(c);
    }

    c.get_rule_api().add_comment(
        "Changing ruletype '" + old_action + "' to 'rewrite' "
        "because the rule has 'replace' option.");

    // update the rule type
    c.get_rule_api().update_rule_action("rewrite");

    return new Replace(c);
}

static const ConvertMap rule_replace =
{
    "replace",
    ctor,
};

const ConvertMap* replace_map = &rule_replace;
} // namespace rules

