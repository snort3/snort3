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
// cd_igmp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/packet.h"
#include "protocols/ipv4_options.h"


namespace
{


#define CD_IGMP_NAME "igmp"

static const RuleMap igmp_rules[] =
{
    { DECODE_IGMP_OPTIONS_DOS, "(" CD_IGMP_NAME ") DOS IGMP IP Options validation attempt" },
    { 0, nullptr }
};


class IgmpModule : public DecodeModule
{
public:
    IgmpModule() : DecodeModule(CD_IGMP_NAME) {}

    const RuleMap* get_rules() const
    { return igmp_rules; }
};



class IgmpCodec : public Codec
{
public:
    IgmpCodec() : Codec(CD_IGMP_NAME){};
    ~IgmpCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};


} // namespace





bool IgmpCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{
    if (raw_len >= 1 && raw_pkt[0] == 0x11)
    {
        const uint8_t* ip_opt_data = p->ip_api.get_ip_opt_data();

        if (ip_opt_data != nullptr) {
            if (p->ip_api.get_ip_opt_len() >= 2) {
                if (*(ip_opt_data) == 0 && *(ip_opt_data+1) == 0)
                {
                    codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
                    return false;
                }
            }
        }


        ip::IpOptionIterator iter(p->ip_api.get_ip4h(), p);
        for (const ip::IpOptions& opt : iter)
        {
            /* All IGMPv2 packets contain IP option code 148 (router alert).
               This vulnerability only applies to IGMPv3, so return early. */
            if (opt.code == ip::IPOptionCodes::RTRALT)
            {
                return true; /* No alert. */
            }

            if (opt.len == 3)
            {
                codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
                return true;
            }
        }
    }
    return true;
}

void IgmpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_IGMP);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new IgmpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new IgmpCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi igmp_api =
{
    {
        PT_CODEC,
        CD_IGMP_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
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
    &igmp_api.base,
    nullptr
};
#else
const BaseApi* cd_igmp = &igmp_api.base;
#endif
