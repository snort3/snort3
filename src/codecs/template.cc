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
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"


namespace
{

class NameCodec : public Codec
{
public:
    NameCodec() : Codec("NAME"){};
    ~NameCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&){};
    
};


struct CdPegs{
    PegCount processed = 0;
    PegCount discards = 0;
};

std::vector<const char*> peg_names =
{
    "NameCodec_processed",
    "NameCodec_discards",
};

} // namespace

static THREAD_LOCAL CdPegs counts;
static CdPegs gcounts;


bool NameCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{

}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


void NameCodec::get_data_link_type(std::vector<int>&)
{
//    v.push_back(DLT_ID);
}

void NameCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
//    v.push_back(PROTO_TYPE);
}

static Codec* ctor()
{
    return new NameCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static void sum()
{
    sum_stats((PegCount*)&gcounts, (PegCount*)&counts, peg_names.size());
    memset(&counts, 0, sizeof(counts));
}

static void stats(std::vector<PegCount> g_peg_counts, std::vector<const char*> g_peg_names)
{
    std::memcpy(&g_peg_counts, &counts, sizeof(CdPegs));
    g_peg_names.insert(g_peg_names.end(), peg_names.begin(), peg_names.end());
}


static const char* name = "name_codec";
static const CodecApi codec_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    sum, // sum
    stats  // stats
};

