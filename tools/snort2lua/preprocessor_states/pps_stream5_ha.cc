//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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
// pps_stream5_ha.cc author Pooja Awasthi <poawasth@cisco.com>

#include <sstream>
#include <string>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class StreamHa : public ConversionState
{
public:
    StreamHa(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool StreamHa::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("high_availability");
    table_api.add_diff_option_comment("stream5_ha", "high_availability");

    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        if (!(arg_stream >> keyword))
            tmpval = false;

        if (keyword == "min_session_lifetime")
        {
            table_api.add_diff_option_comment("min_session_lifetime", "min_age");
            tmpval = parse_int_option("min_age", arg_stream , false);
        }
        else if (keyword == "min_sync_interval")
        {
            table_api.add_diff_option_comment("min_sync_interval", "min_sync");
            tmpval = parse_int_option("min_sync", arg_stream,false);
        }
        else if (keyword == "use_daq")
        {
            table_api.add_diff_option_comment("use_daq", "daq_channel");
            tmpval = table_api.add_option("daq_channel", true);
        }
        else if (keyword == "startup_input_file")
            tmpval = parse_deleted_option("startup_input_file", arg_stream);
        else if (keyword == "runtime_output_file")
            tmpval = parse_deleted_option("runtime_output_file", arg_stream);
        else if (keyword == "shutdown_output_file")
            tmpval = parse_deleted_option("shutdown_output_file", arg_stream);
        else if (keyword == "use_side_channel")
            table_api.add_unsupported_comment("use_side_channel");
        else
            tmpval = false;

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, arg_stream.str());
            retval = false;
        }
    }
    table_api.close_table(); // ha stream
    return retval;
}
/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new StreamHa(c);
}

static const ConvertMap preprocessor_stream_ha =
{
    "stream5_ha",
    ctor,
};

const ConvertMap* stream_ha_map = &preprocessor_stream_ha;
} // namespace preprocessors
