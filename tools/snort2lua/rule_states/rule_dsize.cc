//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_dsize.cc author Russ Combs <rucombs@cisco.com>
// (based on the amazing original work by Josh)

#include <string>
//#include <cstdlib>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Dsize : public ConversionState
{
public:
    Dsize(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Dsize::convert(std::istringstream& data_stream)
{
    std::string args = util::get_rule_option_args(data_stream);
    size_t ltgt = args.find("<>");

    if ( ltgt != std::string::npos )
    {
        rule_api.add_comment("dsize: option change: '<>' --> '<=>'");
        args.insert(ltgt+1, "=");
    }
    rule_api.add_option("dsize", args);
    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* dsize_ctor(Converter& c)
{ return new Dsize(c); }

static const ConvertMap rule_dsize =
{
    "dsize",
    dsize_ctor,
};

const ConvertMap* dsize_map = &rule_dsize;
} // namespace rules

