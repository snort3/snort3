/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// pps_ftp_telnet.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace {

class FtpTelnet : public ConversionState
{
public:
    FtpTelnet(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~FtpTelnet() {};
    virtual bool convert(std::istringstream& data_stream);
private:
    bool add_ftp_n_telnet_option(std::string opt_name, bool val);
    void add_ftp_n_telnet_deprecated(std::string opt_name);
};

} // namespace

bool FtpTelnet::add_ftp_n_telnet_option(std::string opt_name, bool val)
{
    bool retval;

    ld->open_table("telnet");
    retval = ld->add_option_to_table(opt_name, val);
    ld->close_table();
    ld->open_table("ftp_server");
    retval = ld->add_option_to_table(opt_name, val) && retval;
    ld->close_table();
    return retval;
}

void FtpTelnet::add_ftp_n_telnet_deprecated(std::string opt_name)
{
    ld->open_table("telnet");
    ld->add_deprecated_comment(opt_name);
    ld->close_table();
    ld->open_table("ftp_server");
    ld->add_deprecated_comment(opt_name);
    ld->close_table();
}

bool FtpTelnet::convert(std::istringstream& data_stream)
{

    std::string keyword;
    std::string s_value;

    // using this to keep track of any errors.  I want to convert as much 
    // as possible while being aware something went wrong
    bool retval = true;

    if(data_stream >> keyword)
    {
        if(keyword.compare("global"))
        {
            cv->log_error("preprocessor ftp_telnet: requires the 'global' keyword");
            return false;
        }
    }

    while(data_stream >> keyword)
    {
        if(!keyword.compare("check_encrypted"))
            retval = add_ftp_n_telnet_option("check_encrypted", true);

        else if(!keyword.compare("inspection_type"))
            add_ftp_n_telnet_deprecated("inspection_type");

        else if(!keyword.compare("encrypted_traffic"))
        {
            data_stream >> s_value;

            if(s_value.compare("yes"))
                retval = add_ftp_n_telnet_option("encrypted_traffic", true) && retval;

            else
                retval = add_ftp_n_telnet_option("encrypted_traffic", false) && retval;
            
        }

        else
            retval = false;

    }

    return retval;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new FtpTelnet(cv, ld);
}

static const ConvertMap preprocessor_ftptelnet = 
{
    "ftp_telnet",
    ctor,
};

const ConvertMap* ftptelnet_map = &preprocessor_ftptelnet;
