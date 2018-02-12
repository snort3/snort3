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
// pps_gtp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/util_binder.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class Gtp : public ConversionState
{
public:
    Gtp(Converter& c) : ConversionState(c)
    { converted_args = false; }

    ~Gtp() override;
    bool convert(std::istringstream& data_stream) override;

private:
    bool converted_args;
};
} // namespace

Gtp::~Gtp()
{
    if (converted_args)
        return;

    auto& bind = cv.make_binder();
    bind.set_when_proto("udp");
    bind.add_when_port("2123");
    bind.add_when_port("3386");
    bind.set_use_type("gtp_inspect");

    table_api.open_table("gtp_inspect");
    table_api.close_table();
}

bool Gtp::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("udp");
    bind.set_use_type("gtp_inspect");

    converted_args = true;

    table_api.open_table("gtp_inspect");

    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && keyword == "{")
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports <bracketed_port_list>");
                retval = false;
            }
        }

        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
    {
        bind.add_when_port("2123");
        bind.add_when_port("3386");
    }

    table_api.close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Gtp(c);
}

static const ConvertMap preprocessor_gtp =
{
    "gtp",
    ctor,
};

const ConvertMap* gtp_map = &preprocessor_gtp;
} // namespace preprocessors
