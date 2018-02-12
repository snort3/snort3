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
// pps_ssl.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Ssl : public ConversionState
{
public:
    Ssl(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Ssl::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("ssl");

    table_api.open_table("ssl");

    // parse the file configuration
    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "noinspect_encrypted")
            table_api.add_deleted_comment("noinspect_encrypted");

        else if (keyword == "trustservers")
            tmpval = table_api.add_option("trust_servers", true);

        else if (keyword == "max_heartbeat_length")
        {
            tmpval = parse_int_option("max_heartbeat_length", arg_stream, false);
        }
        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if (arg_stream >> keyword)
            {
                if (keyword == "{")
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
        bind.add_when_port("443");
        bind.add_when_port("465");
        bind.add_when_port("563");
        bind.add_when_port("639");
        bind.add_when_port("989");
        bind.add_when_port("992");
        bind.add_when_port("993");
        bind.add_when_port("994");
        bind.add_when_port("995");
        bind.add_when_port("7801");
        bind.add_when_port("7802");
        bind.add_when_port("7900");
        bind.add_when_port("7901");
        bind.add_when_port("7902");
        bind.add_when_port("7903");
        bind.add_when_port("7904");
        bind.add_when_port("7905");
        bind.add_when_port("7906");
        bind.add_when_port("7907");
        bind.add_when_port("7908");
        bind.add_when_port("7909");
        bind.add_when_port("7910");
        bind.add_when_port("7911");
        bind.add_when_port("7912");
        bind.add_when_port("7913");
        bind.add_when_port("7914");
        bind.add_when_port("7915");
        bind.add_when_port("7916");
        bind.add_when_port("7917");
        bind.add_when_port("7918");
        bind.add_when_port("7919");
        bind.add_when_port("7920");
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Ssl(c);
}

static const ConvertMap preprocessor_ssl =
{
    "ssl",
    ctor,
};

const ConvertMap* ssl_map = &preprocessor_ssl;
}

