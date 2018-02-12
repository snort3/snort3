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
// config_memcaps.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option>
class Memcap : public ConversionState
{
public:
    Memcap(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option>
bool Memcap<snort_option, lua_table, lua_option>::convert(std::istringstream& data_stream)
{
    std::string memcap;

    if ((!(data_stream >> memcap)) || (memcap != "memcap"))
    {
        return false;
    }

    table_api.open_table(*lua_table);
    bool retval1 = table_api.add_diff_option_comment("config " + *snort_option + ":",
        "event_filter_memcap");
    bool retval2 = parse_int_option(*lua_option, data_stream, false);
    table_api.close_table();

    // stop parsing, even if additional options available
    data_stream.setstate(std::ios::eofbit);
    return retval1 && retval2;
}

template<const std::string* snort_option,
const std::string* lua_table,
const std::string* lua_option>
static ConversionState* ctor(Converter& c)
{
    return new Memcap<snort_option, lua_table, lua_option>(c);
}
} // namespace

/**************************
 *******  A P I ***********
 **************************/

static const std::string alerts = "alerts";
static const std::string detection_filter = "detection_filter";
static const std::string detection_filter_memcap = "detection_filter_memcap";
static const std::string event_filter = "event_filter";
static const std::string event_filter_memcap = "event_filter_memcap";
static const std::string rate_filter = "rate_filter";
static const std::string rate_filter_memcap = "rate_filter_memcap";
static const std::string threshold = "threshold";

static const ConvertMap detection_filter_api =
{
    detection_filter,
    ctor<& detection_filter, & alerts, & detection_filter_memcap>,
};

static const ConvertMap event_filter_api =
{
    event_filter,
    ctor<& event_filter, & alerts, & event_filter_memcap>,
};

static const ConvertMap rate_filter_api =
{
    rate_filter,
    ctor<& rate_filter, & alerts, & rate_filter_memcap>,
};

static const ConvertMap threshold_api =
{
    threshold,
    ctor<& threshold, & alerts, & event_filter_memcap>,
};

const ConvertMap* detection_filter_map = &detection_filter_api;
const ConvertMap* event_filter_map = &event_filter_api;
const ConvertMap* rate_filter_map = &rate_filter_api;
const ConvertMap* threshold_map = &threshold_api;
} // namespace config

