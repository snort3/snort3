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
// preprocessor.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "preprocessor_states/preprocessor_api.h"

namespace keywords
{
namespace
{
class Preprocessor : public ConversionState
{
public:
    Preprocessor(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Preprocessor::convert(std::istringstream& data_stream)
{
    std::string keyword;

    if (util::get_string(data_stream, keyword, ":"))
    {
        const ConvertMap* map = util::find_map(
            preprocessors::get_preprocessor_api(), keyword, false);

        if (map)
        {
            if (data_stream.peek() == EOF)
                cv.set_empty_args(true);
            /* cv.set_state() deletes this ConversionState object, so must return immediately after */
            cv.set_state(map->ctor(cv));
            return true;
        }
        data_api.failed_conversion(data_stream, "preprocessor " + keyword + ":");
    }
    else
    {
        data_api.failed_conversion(data_stream);
    }

    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Preprocessor(c); }

static const ConvertMap keyword_preprocessor =
{
    "preprocessor",
    ctor,
};

const ConvertMap* preprocessor_map = &keyword_preprocessor;
} // namespace keywords

