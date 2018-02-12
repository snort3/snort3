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
// kws_output.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "output_states/output_api.h"

namespace keywords
{
namespace
{
class Output : public ConversionState
{
public:
    Output(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Output::convert(std::istringstream& data_stream)
{
    std::string keyword;

    if (data_stream >> keyword)
    {
        if (keyword.back() == ':')
            keyword.pop_back();

        const ConvertMap* map = util::find_map(output::output_api, keyword);
        if (map)
        {
            cv.set_state(map->ctor(cv));
            return true;
        }
    }

    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Output(c); }

static const ConvertMap keyword_output =
{
    "output",
    ctor,
};

const ConvertMap* output_map = &keyword_output;
} // namespace keywords

