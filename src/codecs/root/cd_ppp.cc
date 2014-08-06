/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdint>
#include "framework/codec.h"
#include "main/snort.h"



namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#ifndef PPP_NAME
#define PPP_NAME "point_to_point"
#endif

class PPPCodec : public Codec
{
public:
    PPPCodec() : Codec(PPP_NAME){}
    ~PPPCodec() {}


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    virtual void get_data_link_type(std::vector<int>&);
};

} // namespace


#ifndef DLT_PPP
static constexpr int DLT_PPP = 51;
#endif

static constexpr uint8_t CHDLC_ADDR_BROADCAST = 0xff;
static constexpr uint8_t CHDLC_CTRL_UNNUMBERED = 0x03;


void PPPCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_PPP);
}


bool PPPCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet* /*p*/, uint16_t& lyr_len, uint16_t& next_prot_id)
{
    if(raw_len < 2)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return false;
    }

    if(raw_pkt[0] == CHDLC_ADDR_BROADCAST && raw_pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        lyr_len = 2;
    }

    next_prot_id = ETHERTYPE_PPP;
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{
    return new PPPCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi ppp_api =
{
    {
        PT_CODEC,
        PPP_NAME,
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

