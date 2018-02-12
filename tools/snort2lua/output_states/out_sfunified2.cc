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
// out_sfunified2.cc author Michael Altizer <mialtize@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace output
{
    namespace
    {
        class SfUnified2 : public ConversionState
        {
        public:
            SfUnified2(Converter& c) : ConversionState(c) { }
            bool convert(std::istringstream& data_stream) override;
        };

    } // namespace


    bool SfUnified2::convert(std::istringstream& data_stream)
    {
        std::string args;
        bool retval = true;

        table_api.open_table("sfunified2_logger");

        while (std::getline(data_stream, args, ','))
        {
            bool tmpval = true;
            std::string keyword;

            std::istringstream arg_stream(args);
            arg_stream >> keyword;

            if (keyword.empty())
                continue;

            else if (keyword == "nostamp")
                tmpval = table_api.add_option("no_timestamp", true);

            else if (keyword == "mpls_event_types")
                tmpval = table_api.add_deleted_comment("mpls_event_types");

            else if (keyword == "vlan_event_types")
                tmpval = table_api.add_deleted_comment("vlan_event_types");

            else if (keyword == "filename")
                tmpval = parse_string_option("filename", arg_stream);

            else if (keyword == "limit")
                tmpval = parse_int_option("file_size_limit", arg_stream, false);

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
        c.get_table_api().open_top_level_table("sfunified2_logger"); // in case there are no arguments
        c.get_table_api().close_table();
        return new SfUnified2(c);
    }

    static const ConvertMap sfunified2_api =
    {
        "sf_unified2",
        ctor,
    };

    const ConvertMap* sfunified2_map = &sfunified2_api;
} // output namespace

