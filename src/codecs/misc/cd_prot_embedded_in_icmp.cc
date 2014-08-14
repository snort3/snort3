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
// cd_prot_embedded_in_icmp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#ifndef ProtEmbeddedInIcmp_NAME
#define ProtEmbeddedInIcmp_NAME "prot_embedded_in_icmp"
#endif

class ProtEmbeddedInIcmp : public Codec
{
public:
    ProtEmbeddedInIcmp() : Codec(ProtEmbeddedInIcmp_NAME){};
    ~ProtEmbeddedInIcmp() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
};

} // namespace


void ProtEmbeddedInIcmp::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(PROT_EMBEDDED_IN_ICMP);
}

bool ProtEmbeddedInIcmp::decode(const uint8_t* /*raw_pkt*/, const uint32_t& raw_len,
        Packet* /*p*/, uint16_t& lyr_len, uint16_t& /*next_prot_id*/)
{

    // Since the previous layer already set the correct p->proto_bits,
    // there is really nothing to do here.  This layer is actually
    // a placeholder so I can easily find this layer's data at some
    // other point in Snort++.

    lyr_len = raw_len; // so I can access len when encoding
    return true;
}


bool ProtEmbeddedInIcmp::encode(EncState* enc, Buffer* out, const uint8_t* raw_in)
{
    uint16_t lyr_len = enc->p->layers[enc->layer-1].length;


    if (icmp::ICMP_UNREACH_DATA_LEN < lyr_len)
        lyr_len = icmp::ICMP_UNREACH_DATA_LEN;

    if (!update_buffer(out, lyr_len))
        return false;


    memcpy(out->base, raw_in, lyr_len);
    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{
    return new ProtEmbeddedInIcmp();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi prot_embedded_in_icmp_api =
{
    {
        PT_CODEC,
        ProtEmbeddedInIcmp_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
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
    &prot_embedded_in_icmp_api.base,
    nullptr
};
#else
const BaseApi* cd_prot_embedded_in_icmp = &prot_embedded_in_icmp_api.base;
#endif
