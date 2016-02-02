//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// config_alertfile.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Alertfile : public ConversionState
{
public:
    Alertfile(Converter& c) : ConversionState(c) { }
    virtual ~Alertfile() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool Alertfile::convert(std::istringstream& data_stream)
{
    std::string filename = util::get_remain_data(data_stream);

    if (filename.empty())
    {
        data_api.failed_conversion(data_stream, "<missing_filename>");
        return false;
    }

    /*
     * In Snort, config alertfile: is actually only used by full and fast
     * outputs.  So, keep that functionality here.
     */

    table_api.open_table("alert_full");
    table_api.add_diff_option_comment("config alertfile:", "alert_full.file");

    if (!table_api.option_exists("file"))
        table_api.add_option("file", filename);
    else
        table_api.add_comment("config alertfile: " + filename +
            " not added because a different file already exists");

    table_api.close_table();

    table_api.open_table("alert_fast");
    table_api.add_diff_option_comment("config alertfile:", "alert_fast.file");

    if (!table_api.option_exists("file"))
        table_api.add_option("file", filename);
    else
        table_api.add_comment("config alertfile: " + filename +
            " not added because a different file already exists");

    table_api.close_table();

    // stop parsing, even if additional options available
    data_stream.setstate(std::ios::eofbit);
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Alertfile(c); }

static const ConvertMap alertfile_api =
{
    "alertfile",
    ctor,
};

const ConvertMap* alertfile_map = &alertfile_api;
} // namespace config

