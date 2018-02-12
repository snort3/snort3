//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_sip.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Sip : public ConversionState
{
public:
    Sip(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

};
} // namespace

bool Sip::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_use_type("sip");
    table_api.open_table("sip");

    // parse the file configuration
    while (util::get_string(data_stream, keyword, ",;"))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "disabled")
            table_api.add_deleted_comment("disabled");

        else if (keyword == "ignore_call_channel")
        {
            tmpval = table_api.add_option("ignore_call_channel", true);
        }

        else if (keyword == "methods")
            tmpval = parse_curly_bracket_list("methods", arg_stream);

        else if (keyword == "max_call_id_len")
        {
            tmpval = parse_int_option("max_call_id_len", arg_stream, false);
        }

        else if (keyword == "max_contact_len")
        {
            tmpval = parse_int_option("max_contact_len", arg_stream, false);
        }

        else if (keyword == "max_content_len")
        {
            tmpval = parse_int_option("max_content_len", arg_stream, false);
        }

        else if (keyword == "max_dialogs")
        {
            tmpval = parse_int_option("max_dialogs", arg_stream, false);
        }

        else if (keyword == "max_from_len")
        {
            tmpval = parse_int_option("max_from_len", arg_stream, false);
        }

        else if (keyword == "max_requestName_len")
        {
            tmpval = parse_int_option("max_requestName_len", arg_stream, false);
        }

        else if (keyword == "max_sessions")
        {
            table_api.add_deleted_comment("max_sessions");
        }

        else if (keyword == "max_to_len")
        {
            tmpval = parse_int_option("max_to_len", arg_stream, false);
        }

        else if (keyword == "max_uri_len")
        {
            tmpval = parse_int_option("max_uri_len", arg_stream, false);
        }

        else if (keyword == "max_via_len")
        {
            tmpval = parse_int_option("max_via_len", arg_stream, false);
        }

        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if ((arg_stream >> keyword) && keyword == "{")
            {
                while (arg_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(arg_stream, "ports <bracketed_port_list>");
                retval = false;
            }
        }

        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(arg_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
    {
        bind.add_when_port("5060");
        bind.add_when_port("5061");
        bind.add_when_port("5600");
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Sip(c);
}

static const ConvertMap preprocessor_sip =
{
    "sip",
    ctor,
};

const ConvertMap* sip_map = &preprocessor_sip;
}

