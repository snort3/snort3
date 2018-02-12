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
// out_test.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace output
{
namespace
{
class AlertTest : public ConversionState
{
public:
    AlertTest(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool AlertTest::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string args = std::string();
    bool retval = true;

    table_api.open_top_level_table("alert_test");

    // re-using
    while (std::getline(data_stream, args, ','))
    {
        bool tmpval = true;

        std::istringstream arg_stream(args);

        if (!(arg_stream >> keyword))
        {
            retval = false;
            continue;
        }

        if (keyword == "stdout")
            tmpval = table_api.add_deleted_comment("stdout");

        else if (keyword == "session")
            tmpval = table_api.add_option("session", true);

        else if (keyword == "rebuilt")
            tmpval = table_api.add_option("rebuilt", true);

        else if (keyword == "msg")
            tmpval = table_api.add_option("msg", true);

        else if (keyword == "file")
            table_api.add_deleted_comment("file");

        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_top_level_table("alert_test"); // in case there are no arguments
    c.get_table_api().close_table();
    return new AlertTest(c);
}

static const ConvertMap alert_test_api =
{
    "alert_test",
    ctor,
};

const ConvertMap* alert_test_map = &alert_test_api;
} // namespace output

