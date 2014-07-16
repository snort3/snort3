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
// pps_arpspoof.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{

namespace {

class ArpSpoof : public ConversionState
{
public:
    ArpSpoof(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~ArpSpoof() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool ArpSpoof::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    ld->open_table("arp_spoof");

    while(data_stream >> keyword)
    {

        if(!keyword.compare("-unicast"))
            retval = ld->add_option_to_table("unicast", true) && retval;

        else 
            retval = false;
    }

    return retval;    
}

/*******  A P I ***********/

static ConversionState* arpspoof_ctor(Converter* cv, LuaData* ld)
{
    return new ArpSpoof(cv, ld);
}

static const ConvertMap preprocessor_arpspoof = 
{
    "arpspoof",
    arpspoof_ctor,
};

const ConvertMap* arpspoof_map = &preprocessor_arpspoof;



/********************************
 *******  ArpSpoof Host *********
 ********************************/


namespace {

class ArpSpoofHost : public ConversionState
{
public:
    ArpSpoofHost(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~ArpSpoofHost() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool ArpSpoofHost::convert(std::istringstream& data_stream)
{
    std::string ip, mac;

    bool retval = true;
    ld->open_table("arp_spoof");
    ld->open_table("hosts");

    while(data_stream >> ip &&
          data_stream >> mac)
    {
        ld->open_table();
        ld->add_option_to_table("ip", ip);
        ld->add_option_to_table("mac", mac);
        ld->close_table();

        ip.clear();
        mac.clear();
    }

    if (!ip.empty())
        return false;

    return retval;    
}

/*******  A P I ***********/

static ConversionState* arpspoof_host_ctor(Converter* cv, LuaData* ld)
{
    return new ArpSpoofHost(cv, ld);
}

static const ConvertMap preprocessor_arpspoof_host = 
{
    "arpspoof_detect_host",
    arpspoof_host_ctor,
};

const ConvertMap* arpspoof_host_map = &preprocessor_arpspoof_host;

} // namespace preprocessors
