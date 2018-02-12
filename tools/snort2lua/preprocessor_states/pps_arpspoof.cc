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
// pps_arpspoof.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class ArpSpoof : public ConversionState
{
public:
    ArpSpoof(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool ArpSpoof::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    table_api.open_table("arp_spoof");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "-unicast")
            table_api.add_deleted_comment("unicast");

        else
            tmpval = false;

        if (!tmpval)
        {
            retval = false;
            data_api.failed_conversion(data_stream, keyword);
        }
    }

    return retval;
}

/*******  A P I ***********/

static ConversionState* arpspoof_ctor(Converter& c)
{
    return new ArpSpoof(c);
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

namespace
{
class ArpSpoofHost : public ConversionState
{
public:
    ArpSpoofHost(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool ArpSpoofHost::convert(std::istringstream& data_stream)
{
    std::string ip, mac;

    bool retval = true;
    table_api.open_table("arp_spoof");
    table_api.open_table("hosts");

    while (data_stream >> ip &&
        data_stream >> mac)
    {
        table_api.open_table();
        table_api.add_option("ip", ip);
        table_api.add_option("mac", mac);
        table_api.close_table();

        ip.clear();
        mac.clear();
    }

    if (!ip.empty())
        return false;

    return retval;
}

/*******  A P I ***********/

static ConversionState* arpspoof_host_ctor(Converter& c)
{
    return new ArpSpoofHost(c);
}

static const ConvertMap preprocessor_arpspoof_host =
{
    "arpspoof_detect_host",
    arpspoof_host_ctor,
};

const ConvertMap* arpspoof_host_map = &preprocessor_arpspoof_host;
} // namespace preprocessors

