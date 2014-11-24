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
// cd_ppp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>
#include "framework/codec.h"
#include "main/snort.h"


#define PPP_NAME "ppp"
#define PPP_HELP_STR "support for point-to-point encapsulation"
#define PPP_HELP ADD_DLT(PPP_HELP_STR, DLT_PPP)

namespace
{

class PPPCodec : public Codec
{
public:
    PPPCodec() : Codec(PPP_NAME){}
    ~PPPCodec() {}


    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};

} // namespace


#ifndef DLT_PPP
static constexpr int DLT_PPP = 9;
#endif

static constexpr uint8_t CHDLC_ADDR_BROADCAST = 0xff;
static constexpr uint8_t CHDLC_CTRL_UNNUMBERED = 0x03;

void PPPCodec::get_data_link_type(std::vector<int>& v)
{ v.push_back(DLT_PPP); }


bool PPPCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if(raw.len < 2)
        return false;

    if(raw.data[0] == CHDLC_ADDR_BROADCAST && raw.data[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        codec.lyr_len = 2;
    }

    codec.next_prot_id = ETHERTYPE_PPP;
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{ return new PPPCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi ppp_api =
{
    {
        PT_CODEC,
        PPP_NAME,
        PPP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr, // mod_ctor
        nullptr, // mod_dtor
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ppp_api.base,
    nullptr
};
#else
const BaseApi* cd_ppp = &ppp_api.base;
#endif

