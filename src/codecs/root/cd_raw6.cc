/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// cd_raw6.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "protocols/protocol_ids.h"
#include <pcap.h>

#define CD_RAW6_NAME "raw6"
#define CD_RAW6_HELP_STR "support for unencapsulated IPv6"
#define CD_RAW6_HELP ADD_DLT(CD_RAW6_HELP_STR, DLT_IPV6)

namespace
{

class Raw6Codec : public Codec
{
public:
    Raw6Codec() : Codec(CD_RAW6_NAME){};
    ~Raw6Codec() {};

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};


} // namespace


// raw packets are predetermined to be ip4 (above) or ip6 (below) by the DLT
bool Raw6Codec::decode(const RawData&, CodecData& data, DecodeData&)
{
    data.next_prot_id = ETHERTYPE_IPV6;
    return true;
}


void Raw6Codec::get_data_link_type(std::vector<int>&v)
{ v.push_back(DLT_IPV6); }


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Raw6Codec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi raw6_api =
{
    {
        PT_CODEC,
        CD_RAW6_NAME,
        CD_RAW6_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &raw6_api.base,
    nullptr
};
#else
const BaseApi* cd_raw6 = &raw6_api.base;
#endif




