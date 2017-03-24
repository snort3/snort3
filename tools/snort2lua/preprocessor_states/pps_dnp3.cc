//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
// pps_dnp3.cc author Maya Dagon <mdagon@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Dnp3 : public ConversionState
{
public:
    Dnp3(Converter& c) : ConversionState(c)
    { converted_args = false; }

    virtual ~Dnp3();
    virtual bool convert(std::istringstream& data_stream);

private:
    bool converted_args;
};
} // namespace

Dnp3::~Dnp3()
{
    if (converted_args)
        return;

    Binder tcp_bind(table_api);
    tcp_bind.set_when_proto("tcp");
    tcp_bind.add_when_port("20000");
    tcp_bind.set_use_type("dnp3");

    Binder udp_bind(table_api);
    udp_bind.set_when_proto("udp");
    udp_bind.add_when_port("20000");
    udp_bind.set_use_type("dnp3");

    table_api.open_table("dnp3");
    table_api.close_table();
}

bool Dnp3::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    Binder tcp_bind(table_api);
    Binder udp_bind(table_api);

    converted_args = true;

    tcp_bind.set_when_proto("tcp");
    tcp_bind.set_use_type("dnp3");
    udp_bind.set_when_proto("udp");
    udp_bind.set_use_type("dnp3");

    table_api.open_table("dnp3");

    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("disabled"))
        {
            table_api.add_deleted_comment("disabled");
        }
        else if (!keyword.compare("memcap"))
        {
            table_api.add_deleted_comment("memcap");
            data_stream >> keyword;
        }
        else if (!keyword.compare("check_crc"))
        {
            table_api.add_option("check_crc", true);
        }
        else if (!keyword.compare("ports"))
        {
            std::string tmp = "";
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && !keyword.compare("{"))
            {
                while (data_stream >> keyword && keyword.compare("}"))
                {
                    ports_set = true;
                    tcp_bind.add_when_port(keyword);
                    udp_bind.add_when_port(keyword);
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
        tcp_bind.add_when_port("20000");
        udp_bind.add_when_port("20000");
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Dnp3(c);
}

static const ConvertMap preprocessor_dnp3 =
{
    "dnp3",
    ctor,
};

const ConvertMap* dnp3_map = &preprocessor_dnp3;
}

