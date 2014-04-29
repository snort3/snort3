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
#if 0

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif
#endif

#include "framework/codec.h"
#include "events/codec_events.h"

namespace
{

class NameCodec : public Codec
{
public:
    NameCodec() : Codec("dstopts"){};
    ~NameCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};

} // anonymous namespace




void NameCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ipv6::ethertype());
    v.push_back(IPPROTO_IPV6);
}

static Codec* ctor()
{
    return new NameCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "name_codec";

static const CodecApi ipv6_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};

