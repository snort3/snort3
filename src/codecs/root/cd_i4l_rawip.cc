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

#include <pcap.h>
#include "framework/codec.h"


#ifdef DLT_I4L_RAWIP

#define I4L_RAW_IP_NAME "i4l_rawip"
#define I4L_RAW_IP_HELP_STR "support for I4L IP"
#define I4L_RAW_IP_HELP ADD_DLT(I4L_RAW_IP_HELP_STR, DLT_I4L_RAWIP)

namespace
{

class I4LRawIpCodec : public Codec
{
public:
    I4LRawIpCodec() : Codec(I4L_RAW_IP_NAME){};
    ~I4LRawIpCodec() {};


    virtual void get_data_link_type(std::vector<int>&);
    virtual bool decode(const RawData&, CodecData&, SnortData&);
};


} // namespace


void I4LRawIpCodec::get_data_link_type(std::vector<int>& v)
{ v.push_back(DLT_I4L_RAWIP); }

/*
 * Function: DecodeI4LRawIPPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */

bool I4LRawIpCodec::decode(const RawData& raw, CodecData& codec, SnortData&)
{
    if(raw.len < 2)
        return false;

    codec.lyr_len = 2;
    codec.next_prot_id = ETHERTYPE_IPV4;
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{ return new I4LRawIpCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi i4l_raw_ip_api =
{
    {
        PT_CODEC,
        I4L_RAW_IP_NAME,
        I4L_RAW_IP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    nullptr, // ginit
    nullptr, // gterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &i4l_raw_ip_api.base,
    nullptr
};
#else
const BaseApi* cd_name = &i4l_raw_ip_api.base;
#endif

#endif /* DLT_I4L_RAWIP */
