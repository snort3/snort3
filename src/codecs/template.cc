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

#include <string.h> // memcpy
#include "framework/codec.h"
#include "codecs/template_module.h"
#include "protocols/packet.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#ifndef CODEC_NAME
#define CODEC_NAME "name"
#endif

class NameCodec : public Codec
{
public:
    NameCodec() : Codec(CODEC_NAME){};
    ~NameCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void log(TextLog* /*log*/, const uint8_t* /*raw_in*/);
    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual void get_data_link_type(std::vector<int>&);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);

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


void NameCodec::get_data_link_type(std::vector<int>&/*v*/)
{
//    v.push_back(DLT_ID);
}

void NameCodec::get_protocol_ids(std::vector<uint16_t>&/*v*/)
{
//    v.push_back(PROTO_TYPE);
}

bool NameCodec::decode(const uint8_t *raw_pkt, const uint32_t& /*raw_len*/,
        Packet* /*p*/, uint16_t& lyr_len, uint16_t& next_prot_id)
{
    // reinterpret the raw data into this codec's data format
    const NameHdr *hdr = reinterpret_cast<const NameHdr *>(raw_pkt);

    // DO SOME STUFF

    // set the fields which will be sent back to the packet manager
    lyr_len = hdr->len;
    next_prot_id = hdr->next_protocol;

    return true;
}


bool NameCodec::encode(EncState *enc, Buffer* out, const uint8_t* raw_in)
{
    // get the length of the decoded protocol

    uint16_t decoded_length = enc->p->layers[enc->layer-1].length;

    // allocate space for this protocols encoded data
    if (!update_buffer(out, decoded_length))
        return false;

    // ALTERNATIVELY, if you knwo the exact length you want to add
    // update_buffer(enc, sizeof(NameHdr));

    // MUST BE DONE AFTER UPDATE_BUFFER!!
    // get a pointer to the raw packet input and output buffer.  
    const NameHdr *hi = reinterpret_cast<const NameHdr*>(raw_in);
    NameHdr *ho = reinterpret_cast<NameHdr*>(out->base);

    // copy raw input and new output.  You probably want to do
    // something slightly more useful.
    memcpy(ho, hi, decoded_length);
    return true;
}

bool NameCodec::update(Packet*, Layer*, uint32_t* /*len*/)
{
    return true;
}

void NameCodec::format(EncodeFlags,
                       const Packet* /*p*/,
                       Packet* /*c*/,
                       Layer* /*l*/)
{
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

/*
 * Modules create custom configuration options which can be used in snort.lua.
 * If you don't want any configuration options, remove the mod_ctor
 * and mod_dtor functions from the api below.  See documentation for additional
 * details regarding Modules
 */
static Module* mod_ctor()
{
    return new NameModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static void ginit()
{
    // initialize global variables
}

static void gterm()
{
    // cleanup any global variables
}

static void tinit()
{
    // initialize thread_local variables
}

static void tterm()
{
    // cleanup any thread_local variables
}

static Codec* ctor(Module*)
{
    return new NameCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi name_api =
{
    {
        PT_CODEC,
        CODEC_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor, // module constructor ( see function for details )
        mod_dtor  // module destructor  ( see function for details )
    },
    ginit, // global initializer
    gterm, // global terminate
    tinit, // thread local initializer
    tterm, // thread local terminate
    ctor,  // constructor --> REQUIRED. return a newly create Codec
    dtor,  // desctructor --> REQUIRED. destory the Codec.
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &name_api.base,
    nullptr
};
#else
const BaseApi* cd_name = &name_api.base;
#endif
