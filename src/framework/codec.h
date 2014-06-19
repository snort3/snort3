/*
** Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef CODEC_H
#define CODEC_H

#include <vector>
#include <cstdint>

#include "main/snort_types.h"
#include "framework/base_api.h"
#include "codecs/sf_protocols.h"
#include "protocols/icmp4.h"
#include "packet.h"

struct Packet;
struct Layer;

enum EncodeType{
    ENC_TCP_FIN,
    ENC_TCP_RST,
    ENC_UNR_NET,
    ENC_UNR_HOST,
    ENC_UNR_PORT,
    ENC_UNR_FW,
    ENC_TCP_PUSH,
    ENC_MAX
};


typedef uint32_t EncodeFlags;
const uint32_t ENC_FLAG_FWD = 0x80000000;  // send in forward direction
const uint32_t ENC_FLAG_SEQ = 0x40000000;  // VAL bits contain seq adj
const uint32_t ENC_FLAG_ID  = 0x20000000;  // use randomized IP ID
const uint32_t ENC_FLAG_NET = 0x10000000;  // stop after innermost network (ip4/6) layer
const uint32_t ENC_FLAG_DEF = 0x08000000;  // stop before innermost ip4 opts or ip6 frag header
const uint32_t ENC_FLAG_RAW = 0x04000000;  // don't encode outer eth header (this is raw ip)
const uint32_t ENC_FLAG_RES = 0x03000000;  // bits reserved for future use
const uint32_t ENC_FLAG_VAL = 0x00FFFFFF;  // bits for adjusting seq and/or ack


struct EncState{
    EncodeType type;
    EncodeFlags flags;

    uint8_t layer;
    const Packet* p;
    uint16_t ip_len;
    uint8_t* ip_hdr;

    const uint8_t* payLoad;
    uint32_t payLen;
    uint8_t proto;
};


// Copied from dnet/blob.h
// * base+off is start of packet
// * base+end is start of current layer
// * base+size-1 is last byte of packet (in) / buffer (out)
struct Buffer {
    uint8_t* base;          /* start of data */
    int off;           /* offset into data */
    int end;           /* end of data */
    int size;          /* size of allocation */
};


// Update's the buffer to contain an additional
static inline bool update_buffer(Buffer* buf, size_t n)
{
    if ( buf->end + n > (unsigned int)buf->size )
    {
        return false;
    }

    buf->end += n;
    buf->base -= n;
    return true;
}


class Codec
{
public:
    virtual ~Codec() { };

    // PKT_MAX = ETHERNET_HEADER_LEN () + VLAN_HEADER (4) + ETHERNET_MTU () + IP_MAXPACKET()

    /* PKT_MAX is sized to ensure that any reassembled packet
     * can accommodate a full datagram at innermost layer
     *
     * ETHERNET_HEADER_LEN == 14
     * VLAN_HEADER == 4
     * ETHERNET_MTU == 1500
     * IP_MAXPACKET ==  65535
     */
    static const uint32_t PKT_MAX = 14 + 4 + 1500 + 65535;

    // Get the codec's name
    inline const char* get_name(){return name; };
    // Registers this Codec's data link type (as defined by libpcap)
    virtual void get_data_link_type(std::vector<int>&) {};
    // Register the code's protocol ID's and Ethertypes
    virtual void get_protocol_ids(std::vector<uint16_t>&) {};
    // decode function
    virtual bool decode(const uint8_t* raw_packet, const uint32_t raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id) = 0;

    // 
    // Encode the current packet. Encoding starts with the innermost
    // layer and working outwards.  All encoders MUST call the update
    // bound function before writing to output buffer.
    // PARAMS:
    //        EncStats * = The current EncState struct
    //        Buffer *out = the buffer struct. When called, out->base pointers
    //              to the already encoded packet! to create more memory, call
    //              update_buffer function!
    //        uint8_t* raw_in =  A pointer to the raw input which was decoded
    virtual bool encode(EncState*, Buffer* /*out*/, const uint8_t* /*raw_in*/) { return true; };

    // update function
    virtual bool update(Packet*, Layer*, uint32_t* /*len*/) { return true; };
    // formatter
    virtual void format(EncodeFlags, const Packet* /*orig*/, Packet* /*clone*/, Layer*) {};
    // used for backwards compatability.
    virtual PROTO_ID get_proto_id() { return PROTO_AH; };


protected:
    Codec(const char* s)
    {
        name = s;
    };


    static inline bool forward(const EncState *e)
    {
        return e->flags & ENC_FLAG_FWD;
    }

    static inline bool reverse(const EncodeFlags f)
    {
        return !(f & ENC_FLAG_FWD);
    }

    static inline uint16_t get_decoded_length(EncState *enc)
    {
        return enc->p->layers[enc->layer-1].length;
    }


    static inline uint8_t buff_diff(Buffer *buf, uint8_t* ho)
    {
        return ((uint8_t*)(buf->base+buf->end)-(uint8_t*)ho);
    }

    static inline icmp4::IcmpCode get_icmp_code (EncodeType et)
    {
        switch ( et ) {
            case EncodeType::ENC_UNR_NET:  return icmp4::IcmpCode::NET_UNREACH;
            case EncodeType::ENC_UNR_HOST: return icmp4::IcmpCode::HOST_UNREACH;
            case EncodeType::ENC_UNR_PORT: return icmp4::IcmpCode::PORT_UNREACH;
            case EncodeType::ENC_UNR_FW:   return icmp4::IcmpCode::PKT_FILTERED;
            default: return icmp4::IcmpCode::PORT_UNREACH;
        }
    }



private:
    const char* name;
};



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


// this is the current version of the api
#define CDAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define CDAPI_PLUGIN_V0 0

typedef Codec* (*CdNewFunc)(Module*);
typedef void (*CdDelFunc)(Codec *);
typedef void (*CdAuxFunc)();

struct CodecApi
{
    BaseApi base;

    // these may be nullptr
    CdAuxFunc ginit;  // initialize global plugin data
    CdAuxFunc gterm;  // clean-up pinit()

    CdAuxFunc tinit;  // initialize thread-local plugin data
    CdAuxFunc tterm;  // clean-up tinit()

    // these must be set
    CdNewFunc ctor;   // get eval optional instance data
    CdDelFunc dtor;   // clean up instance data
};

#endif

