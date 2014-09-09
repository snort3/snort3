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

#include "framework/codec.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include <pcap.h>


namespace
{

#define CD_NULL_NAME "null"

class NullCodec : public Codec
{
public:
    NullCodec() : Codec(CD_NULL_NAME){};
    ~NullCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_data_link_type(std::vector<int>&);

};


} // namespace


static const uint16_t NULL_HDRLEN = 4;

/*
 * Function: DecodeNullPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
bool NullCodec::decode(const uint8_t* /*raw_pkt*/, const uint32_t& raw_len,
        Packet* /*p*/, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    /* do a little validation */
    if(raw_len < NULL_HDRLEN)
        return false;

    lyr_len = NULL_HDRLEN;
    next_prot_id = ETHERTYPE_IPV4;
    return true;
}

void NullCodec::get_data_link_type(std::vector<int>&v)
{
    v.push_back(DLT_NULL);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new NullCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi null_api =
{
    {
        PT_CODEC,
        CD_NULL_NAME,
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
    &null_api.base,
    nullptr
};
#else
const BaseApi* cd_null = &null_api.base;
#endif
