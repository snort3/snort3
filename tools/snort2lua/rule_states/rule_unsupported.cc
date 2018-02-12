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
// rule_unsupported.cc author Michael Altizer <mialtize@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "conversion_state.h"

namespace rules
{
template<const std::string* rule_opt_name, bool has_suboptions>
class UnsupportedRuleOption : public ConversionState
{
public:
    UnsupportedRuleOption(Converter& c) : ConversionState(c)
    {
        c.get_rule_api().make_rule_a_comment();
        c.get_rule_api().add_comment("The '" + *rule_opt_name + "' rule option keyword is no longer supported");
    }

    bool convert(std::istringstream& stream) override
    {
        if (has_suboptions)
            util::get_rule_option_args(stream);
        return set_next_rule_state(stream);
    }
};

/**************************
 *******  A P I ***********
 **************************/

template<const std::string* rule_opt_name, bool has_suboptions>
static ConversionState* unsupported_rule_ctor(Converter& c)
{
    return new UnsupportedRuleOption<rule_opt_name, has_suboptions>(c);
}

static const std::string activated_by = "activated_by";
static const std::string activates = "activates";
static const std::string count = "count";
static const std::string ftpbounce = "ftpbounce";
static const std::string logto = "logto";
static const std::string sameip = "sameip";

static const ConvertMap activated_by_api = { activated_by, unsupported_rule_ctor<&activated_by, true>};
static const ConvertMap activates_api = { activates, unsupported_rule_ctor<&activates, true>};
static const ConvertMap count_api = { count, unsupported_rule_ctor<&count, true>};
static const ConvertMap ftpbounce_api = { ftpbounce, unsupported_rule_ctor<&ftpbounce, false>};
static const ConvertMap logto_api = { logto, unsupported_rule_ctor<&logto, false>};
static const ConvertMap sameip_api = { sameip, unsupported_rule_ctor<&sameip, false>};

const ConvertMap* activated_by_map = &activated_by_api;
const ConvertMap* activates_map = &activates_api;
const ConvertMap* count_map = &count_api;
const ConvertMap* ftpbounce_map = &ftpbounce_api;
const ConvertMap* logto_map = &logto_api;
const ConvertMap* sameip_map = &sameip_api;
} // namespace rules
