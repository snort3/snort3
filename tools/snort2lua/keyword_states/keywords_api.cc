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
// keywords_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "keyword_states/keywords_api.h"

namespace keywords
{
extern const ConvertMap* activate_map;
extern const ConvertMap* attribute_table_map;
extern const ConvertMap* alert_map;
extern const ConvertMap* block_map;
extern const ConvertMap* config_map;
extern const ConvertMap* drop_map;
extern const ConvertMap* dynamic_map;
extern const ConvertMap* dynamicdetection_map;
extern const ConvertMap* dynamicengine_map;
extern const ConvertMap* dynamicpreprocessor_map;
extern const ConvertMap* dynamicoutput_map;
extern const ConvertMap* dynamicsidechannel_map;
extern const ConvertMap* event_filter_map;
extern const ConvertMap* file_map;
extern const ConvertMap* include_map;
extern const ConvertMap* ipvar_map;
extern const ConvertMap* log_map;
extern const ConvertMap* output_map;
extern const ConvertMap* pass_map;
extern const ConvertMap* portvar_map;
extern const ConvertMap* preprocessor_map;
extern const ConvertMap* rate_filter_map;
extern const ConvertMap* reject_map;
extern const ConvertMap* rule_state_map;
extern const ConvertMap* ruletype_map;
extern const ConvertMap* sblock_map;
extern const ConvertMap* sdrop_map;
extern const ConvertMap* sidechannel_map;
extern const ConvertMap* suppress_map;
extern const ConvertMap* threshold_map;
extern const ConvertMap* var_map;

const std::vector<const ConvertMap*> keywords_api =
{
    activate_map,
    attribute_table_map,
    alert_map,
    block_map,
    config_map,
    drop_map,
    dynamic_map,
    dynamicdetection_map,
    dynamicengine_map,
    dynamicpreprocessor_map,
    dynamicoutput_map,
    dynamicsidechannel_map,
    event_filter_map,
    file_map,
    include_map,
    ipvar_map,
    log_map,
    output_map,
    pass_map,
    portvar_map,
    preprocessor_map,
    rate_filter_map,
    reject_map,
    rule_state_map,
    ruletype_map,
    sblock_map,
    sdrop_map,
    sidechannel_map,
    suppress_map,
    threshold_map,
    var_map,
};
} // namespace keywords
