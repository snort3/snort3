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
// pps_ftp_telnet.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class FtpTelnet : public ConversionState
{
public:
    FtpTelnet(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    bool add_ftp_n_telnet_option(const std::string& opt_name, bool val);
    void add_ftp_n_telnet_deprecated(std::istringstream&, const std::string& opt_name);
};
} // namespace

bool FtpTelnet::add_ftp_n_telnet_option(const std::string& opt_name, bool val)
{
    bool retval;

    table_api.open_top_level_table("telnet");
    retval = table_api.add_option(opt_name, val);
    table_api.close_table();
    table_api.open_top_level_table("ftp_server");
    retval = table_api.add_option(opt_name, val) && retval;
    table_api.close_table();
    return retval;
}

void FtpTelnet::add_ftp_n_telnet_deprecated(std::istringstream& data_stream,
    const std::string& opt_name)
{
    std::string tmp;
    data_stream >> tmp;  // eat the next word
    table_api.open_top_level_table("telnet");
    table_api.add_deleted_comment(opt_name);
    table_api.close_table();
    table_api.open_top_level_table("ftp_server");
    table_api.add_deleted_comment(opt_name);
    table_api.close_table();
}

bool FtpTelnet::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string s_value;

    // using this to keep track of any errors.  I want to convert as much
    // as possible while being aware something went wrong
    bool retval = true;

    if (data_stream >> keyword)
    {
        if (keyword != "global")
        {
            data_api.failed_conversion(data_stream, "'global' keyword required");
            return false;
        }
    }

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "check_encrypted")
            tmpval = add_ftp_n_telnet_option("check_encrypted", true);

        else if (keyword == "inspection_type")
            add_ftp_n_telnet_deprecated(data_stream, "inspection_type");

        else if (keyword == "memcap")
            add_ftp_n_telnet_deprecated(data_stream, "memcap");

        else if (keyword == "encrypted_traffic")
        {
            data_stream >> s_value;

            if (s_value == "yes")
                tmpval = add_ftp_n_telnet_option("encrypted_traffic", true);
            else
                tmpval = add_ftp_n_telnet_option("encrypted_traffic", false);
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

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new FtpTelnet(c);
}

static const ConvertMap preprocessor_ftptelnet =
{
    "ftp_telnet",
    ctor,
};

const ConvertMap* ftptelnet_map = &preprocessor_ftptelnet;
} // namespace preprocessors

