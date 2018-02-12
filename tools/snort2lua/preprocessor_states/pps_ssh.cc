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
// pps_ssh.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Ssh : public ConversionState
{
public:
    Ssh(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

};
} // namespace

bool Ssh::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("ssh");

    table_api.open_table("ssh");


    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "autodetect")
            table_api.add_deleted_comment("autodetect");

        else if (keyword == "enable_respoverflow")
            table_api.add_deleted_comment("enable_respoverflow");

        else if (keyword == "enable_ssh1crc32")
            table_api.add_deleted_comment("enable_ssh1crc32");

        else if (keyword == "enable_srvoverflow")
            table_api.add_deleted_comment("enable_srvoverflow");

        else if (keyword == "enable_protomismatch")
            table_api.add_deleted_comment("enable_protomismatch");

        else if (keyword == "enable_badmsgdir")
            table_api.add_deleted_comment("enable_badmsgdir");

        else if (keyword == "enable_paysize")
            table_api.add_deleted_comment("enable_paysize");

        else if (keyword == "enable_recognition")
            table_api.add_deleted_comment("enable_recognition");

        else if (keyword == "max_client_bytes")
        {
            tmpval = parse_int_option("max_client_bytes", data_stream, false);
        }

        else if (keyword == "max_encrypted_packets")
        {
            tmpval = parse_int_option("max_encrypted_packets", data_stream, false);
        }

        else if (keyword == "max_server_version_len")
        {
            tmpval = parse_int_option("max_server_version_len", data_stream, false);
        }

        else if (keyword == "server_ports")
        {
            table_api.add_diff_option_comment("server_ports", "bindings");

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
                data_api.failed_conversion(data_stream, "server_ports <bracketed_port_list>");
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
        bind.add_when_port("22");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Ssh(c);
}

static const ConvertMap preprocessor_ssh =
{
    "ssh",
    ctor,
};

const ConvertMap* ssh_map = &preprocessor_ssh;
}

