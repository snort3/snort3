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
// pps_arp_spoof.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class ArpSpoof : public ConversionState
{
public:
    ArpSpoof(Converter* cv)  : ConversionState(cv) {};
    virtual ~ArpSpoof() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool ArpSpoof::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    cv->open_table("arp_spoof");

    while(data_stream >> keyword)
    {

        if(!keyword.compare("-unicast"))
            retval = cv->add_option_to_table("unicast", true) && retval;

        else 
            retval = false;
    }

    return retval;    
}

/*******  A P I ***********/

static ConversionState* arpspoof_ctor(Converter* cv)
{
    return new ArpSpoof(cv);
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
    ArpSpoofHost(Converter* cv)  : ConversionState(cv) {};
    virtual ~ArpSpoofHost() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool ArpSpoofHost::convert(std::stringstream& data_stream)
{
    std::string ip, mac;

    bool retval = true;
    cv->open_table("arp_spoof");
    cv->open_table("hosts");

    while(data_stream >> ip &&
          data_stream >> mac)
    {
        cv->open_table();
        cv->add_option_to_table("ip", ip);
        cv->add_option_to_table("mac", mac);
        cv->close_table();

        ip.clear();
        mac.clear();
    }

    if (!ip.empty())
        return false;

    return retval;    
}

/*******  A P I ***********/

static ConversionState* arpspoof_host_ctor(Converter* cv)
{
    return new ArpSpoofHost(cv);
}

static const ConvertMap preprocessor_arpspoof_host = 
{
    "arpspoof_detect_host",
    arpspoof_host_ctor,
};

const ConvertMap* arpspoof_host_map = &preprocessor_arpspoof_host;
