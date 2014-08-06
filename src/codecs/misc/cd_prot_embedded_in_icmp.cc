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


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
};

} // namespace


void ProtEmbeddedInIcmp::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(PROT_EMBEDDED_IN_ICMP);
}

bool ProtEmbeddedInIcmp::decode(const uint8_t* /*raw_pkt*/, const uint32_t& /*raw_len*/,
        Packet* /*p*/, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{

    // Since the previous layer already set the correct p->proto_bits,
    // there is really nothing to do here.  This layer is actually
    // a placeholder so I can easily find this layer's data at some
    // other point in Snort++.
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
