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
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"


namespace
{

class IgmpCodec : public Codec
{
public:
    IgmpCodec() : Codec("igmp"){};
    ~IgmpCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};


} // namespace





bool IgmpCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{
    int i, alert = 0;

    if (len >= 1 && raw_pkt[0] == 0x11)
    {
        if (p->ip_options_data != NULL) {
            if (p->ip_options_len >= 2) {
                if (*(p->ip_options_data) == 0 && *(p->ip_options_data+1) == 0)
                {
                    codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
                    return false;
                }
            }
        }

        for(i=0; i< (int) p->ip_option_count; i++) {
            /* All IGMPv2 packets contain IP option code 148 (router alert).
               This vulnerability only applies to IGMPv3, so return early. */
            if (ipv4::is_opt_rtralt(p->ip_options[i].code)) {
                return true; /* No alert. */
            }

            if (p->ip_options[i].len == 1) {
                alert++;
            }
        }

        if (alert > 0)
            codec_events::decoder_event(p, DECODE_IGMP_OPTIONS_DOS);
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

static Codec* ctor()
{
    return new IgmpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "igmp";
static const CodecApi igmp_api =
{
    { 
        PT_CODEC, 
        name, 
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

const BaseApi* cd_igmp = &igmp_api.base;
