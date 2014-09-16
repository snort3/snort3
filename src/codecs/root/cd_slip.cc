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


#include <pcap.h>
#include <cstdint>
#include "framework/codec.h"
#include "protocols/protocol_ids.h"


#define CD_SLIP_NAME "slip"
#define CD_SLIP_HELP_STR "support for slip protocol"
#define CD_SLIP_HELP ADD_DLT(CD_SLIP_HELP_STR, DLT_SLIP)

const uint16_t SLIP_HEADER_LEN = 16;


namespace
{

class SlipCodec : public Codec
{
public:
    SlipCodec() : Codec(CD_SLIP_NAME){};
    ~SlipCodec() {};

    virtual bool decode(const RawData&, CodecData&, SnortData&);
    virtual void get_data_link_type(std::vector<int>&);
};

} // namespace


void SlipCodec::get_data_link_type(std::vector<int>& v)
{
#if DLT_SLIP
    v.push_back(DLT_SLIP);
#endif
}


bool SlipCodec::decode(const RawData& raw, CodecData& codec, SnortData&)
{
    if (raw.len < SLIP_HEADER_LEN)
        return false;

    // set the fields which will be sent back to the packet manager
    codec.lyr_len = SLIP_HEADER_LEN;
    codec.next_prot_id = ETHERTYPE_IPV4;
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{ return new SlipCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi slip_api =
{
    {
        PT_CODEC,
        CD_SLIP_NAME,
        CD_SLIP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &slip_api.base,
    nullptr
};
#else
const BaseApi* cd_slip = &slip_api.base;
#endif
