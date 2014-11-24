/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// template.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h> // memcpy
#include "framework/codec.h"
#include "codecs/codec_module.h"
#include "protocols/packet.h"
#include "framework/module.h"
#include "log/text_log.h"

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#define CODEC_NAME "name"
#define CODEC_HELP "one line help for this codec"

namespace
{

// inherit from CodecModule rather than Module so the GID for
// all codecs are identical. Additionally, all of the SIDS are
// defined in CodecModule. So, when creating new events, you
// only need to look for codec SID collisions in one locations
class NameModule : public CodecModule
{
public:
    NameModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    const RuleMap* get_rules() const override;

private:
    // any structs or options which will be used when constructing
    // the Codec
    bool option1;

};


static const Parameter codec_params[] =
{
    { "parameter1", Parameter::PT_BOOL, nullptr, "false",
      "This is a boolean parameter" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


// rules which will loaded into snort.
// You can now reference these rules by calling a codec_event
// in your main codec's functions
const unsigned sid = 1;
static const RuleMap codec_rules[] =
{
    { sid, "alert message" },
    { 0, nullptr }
};

//-------------------------------------------------------------------------
// template module
//-------------------------------------------------------------------------

NameModule::NameModule() : CodecModule(CODEC_NAME, CODEC_HELP, codec_params)
{ }

bool NameModule::set(const char* /*fqn*/, Value& v, SnortConfig* /*sc*/)
{
    if ( v.is("parameter1") )
        option1 = v.get_bool();

    else
        return false;

    return true;
}

bool NameModule::begin(const char*, int, SnortConfig*)
{
    option1 = false;
    return true;
}

const RuleMap* NameModule::get_rules() const
{ return codec_rules; }


class NameCodec : public Codec
{
public:
    NameCodec() : Codec(CODEC_NAME){};
    ~NameCodec() {};


    // decode(...) must be implemented!!
    bool decode(const RawData&, CodecData&, DecodeData&) override;

    void log(TextLog*, const uint8_t* /*raw_pkt*/, const Packet* const) override;
    void get_protocol_ids(std::vector<uint16_t>&) override;
    void get_data_link_type(std::vector<int>&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState&, Buffer&) override;
    bool update(Packet*, Layer*, uint32_t* len) override;
    void format(EncodeFlags, const Packet* p, Packet* c, Layer*) override;
};

// Create your own Hdr Struct for this layer!
struct NameHdr
{
    uint8_t ver;
    uint8_t next_protocol;
    uint16_t len;
    // additional or different data
};
//constexpr uint16_t NAME_HDR_LEN = 4;  sizeof may return '8' on a 64 bit system

} // namespace


void NameCodec::get_data_link_type(std::vector<int>&/*v*/)
{
//    v.push_back(DLT_ID);
}

void NameCodec::get_protocol_ids(std::vector<uint16_t>&/*v*/)
{
//    v.push_back(PROTO_TYPE);
//    v.push_back(ETHERTYPE);
}

bool NameCodec::decode(const RawData& raw, CodecData& data, DecodeData&)
{
    // reinterpret the raw data into this codec's data format
    const NameHdr* const hdr =
        reinterpret_cast<const NameHdr *>(raw.data);

    // DO SOME STUFF

    // set the fields which will be sent back to the packet manager
    data.lyr_len = hdr->len;
    data.next_prot_id = hdr->next_protocol;

    return true;
}

void NameCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const NameHdr *hdr = reinterpret_cast<const NameHdr *>(raw_pkt);
    TextLog_Print(text_log, "Next:0x%04x", hdr->next_protocol);
}

bool NameCodec::encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState& enc, Buffer& buf)
{

    // allocate space for this protocols encoded data
    if (buf.allocate(raw_len))
        return false;

    // ALTERNATIVELY, if you knwo the exact length you want to add
    // if (!buf.allocate(NAME_HDR_LEN)   //  sizeof gives the padded result == not always accurate
    //      return nullptr;

    // MUST BE DONE AFTER UPDATE_BUFFER!!
    // get a pointer to the raw packet input and output buffer.  

    // copy raw input and new output.  You probably want to do
    // something slightly more useful.
    memcpy(buf.base, raw_in, raw_len);

    // set any fields that we want
    NameHdr* const hdr = reinterpret_cast<NameHdr*>(buf.base);
    hdr->next_protocol = enc.next_proto; // set the 'next' field to the appropriate value.
                                      // The origin next may not have been copied
    hdr->len = buf.size();  // set the size to be the length from the begining of this
                            // packet to the end of the struct.

//    enc.next_proto = PROTO_TYPE;
//    enc.next_ethertype = ETHERTYPE;
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
{ return new NameModule; }

static void mod_dtor(Module* m)
{ delete m; }

// initialize global variables
static void ginit()
{ }

// cleanup any global variables
static void gterm()
{ }

// initialize thread_local variables
static void tinit()
{ }

// cleanup any thread_local variables
static void tterm()
{ }

static Codec* ctor(Module*)
{ return new NameCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi name_api =
{
    {
        PT_CODEC,
        CODEC_NAME,
        CODEC_HELP,
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
