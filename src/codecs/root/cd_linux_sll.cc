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
#include "protocols/linux_sll.h"
#include "main/snort.h"


namespace
{

#define CD_LINUX_SSL_NAME "cd_linux_sll"

class LinuxSllCodec : public Codec
{
public:
    LinuxSllCodec() : Codec(CD_LINUX_SSL_NAME){};
    ~LinuxSllCodec() {};


    virtual void get_data_link_type(std::vector<int>&);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
};

// Create your own Hdr Struct for this layer!
struct NameHdr
{
    uint8_t ver;
    uint8_t next_protocol;
    uint16_t len;
    // additional or different data
};

} // namespace


void LinuxSllCodec::get_data_link_type(std::vector<int>&v)
{
#ifdef DLT_LINUX_SLL
    v.push_back(DLT_LINUX_SLL);
#endif
}

bool LinuxSllCodec::decode(const uint8_t *raw_pkt, const uint32_t raw_len,
        Packet* /*p*/, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    /* do a little validation */
    if(raw_len < SLL_HDR_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < SLL header length (your "
                         "libpcap is broken?)! (%d bytes)\n", raw_len);
        }
        return false;
    }
    /* lay the ethernet structure over the packet data */
    const linux_sll::SLLHdr* sllh = reinterpret_cast<const linux_sll::SLLHdr*>(raw_pkt);

    /* grab out the network type */
    next_prot_id = ntohs(sllh->sll_protocol);
    lyr_len = SLL_HDR_LEN;
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new LinuxSllCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi linux_ssl_api =
{
    {
        PT_CODEC,
        CD_LINUX_SSL_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
    },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    ctor,
    dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &linux_ssl_api.base,
    nullptr
};
#else
const BaseApi* cd_linux_sll = &linux_ssl_api.base;
#endif

