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
#include "protocols/ipv4.h"
#include "protocols/checksum.h"

namespace
{

class PgmCodec : public Codec
{
public:
    PgmCodec() : Codec("pgm"){};
    ~PgmCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};


static const uint16_t IPPROTO_ID_PGM = 113;
static const int PGM_NAK_ERR = -1;
static const int PGM_NAK_OK = 0;
static const int PGM_NAK_VULN = 1;

typedef struct _PGM_NAK_OPT
{
    uint8_t type;     /* 02 = vuln */
    uint8_t len;
    uint8_t res[2];
    uint32_t seq[1];    /* could be many many more, but 1 is sufficient */
} PGM_NAK_OPT;

typedef struct _PGM_NAK
{
    uint32_t  seqnum;
    uint16_t  afil1;
    uint16_t  res1;
    uint32_t  src;
    uint16_t  afi2;
    uint16_t  res2;
    uint32_t  multi;
    PGM_NAK_OPT opt;
} PGM_NAK;

typedef struct _PGM_HEADER
{
    uint16_t srcport;
    uint16_t dstport;
    uint8_t  type;
    uint8_t  opt;
    uint16_t checksum;
    uint8_t  gsd[6];
    uint16_t length;
    PGM_NAK  nak;
} PGM_HEADER;


} // namespace

/* This PGM NAK function started off as an SO rule, sid 8351. */
static inline int pgm_nak_detect (uint8_t *data, uint16_t length) {
    uint16_t data_left;
    uint16_t  checksum;
    PGM_HEADER *header;

    if (NULL == data) {
        return PGM_NAK_ERR;
    }

    /* request must be bigger than 44 bytes to cause vuln */
    if (length <= sizeof(PGM_HEADER)) {
        return PGM_NAK_ERR;
    }

    header = (PGM_HEADER *) data;

    if (8 != header->type) {
        return PGM_NAK_ERR;
    }

    if (2 != header->nak.opt.type) {
        return PGM_NAK_ERR;
    }


    /*
     * alert if the amount of data after the options is more than the length
     * specified.
     */


    data_left = length - 36;
    if (data_left > header->nak.opt.len) {

        /* checksum is expensive... do that only if the length is bad */
        if (header->checksum != 0) {
            checksum = checksum::cksum_add((unsigned short*)data, (int)length);
            if (checksum != 0)
                return PGM_NAK_ERR;
        }

        return PGM_NAK_VULN;
    }

    return PGM_NAK_OK;
}


//-------------------------------------------------------------------------
// private functions
//-------------------------------------------------------------------------

bool PgmCodec::decode(const uint8_t* /*raw_pkt*/, const uint32_t /*len*/, 
        Packet *p, uint16_t& /*lyr_len*/, uint16_t& /*next_prot_id*/)
{
    if ( pgm_nak_detect((uint8_t *)p->data, p->dsize) == PGM_NAK_VULN )
        codec_events::decoder_event(p, DECODE_PGM_NAK_OVERFLOW);
    return true;
}

void PgmCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_PGM);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new PgmCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const char* name = "pgm";
static const CodecApi pgm_api =
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

const BaseApi* cd_pgm = &pgm_api.base;

