//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// codec.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef FRAMEWORK_CODEC_H
#define FRAMEWORK_CODEC_H

// Codec is a type of plugin that provides protocol-specific encoding and
// decoding.

#include <cstdint>
#include <vector>

#include "framework/base_api.h"
#include "framework/decode_data.h"
#include "utils/cpp_macros.h"

struct TextLog;
struct _daq_pkthdr;

namespace snort
{
enum CodecSid : uint32_t;

namespace ip
{
class IpApi;
}
namespace tcp
{
struct TCPHdr;
}
namespace udp
{
struct UDPHdr;
}
namespace icmp
{
struct ICMPHdr;
}

class Flow;
struct Layer;
struct Packet;

// Used by root codecs to add their DLT to their HELP string
#define ADD_DLT(help, x) help " (DLT " STRINGIFY_MX(x) ")"

constexpr uint8_t MIN_TTL = 64;
constexpr uint8_t MAX_TTL = 255;

struct RawData
{
    const _daq_pkthdr* pkth;
    const uint8_t* data;
    uint32_t len;

    RawData(const _daq_pkthdr*, const uint8_t*);
};

/*  Decode Flags */
constexpr uint16_t CODEC_DF = 0x0001;    /* don't fragment flag */

// packet may have incorrect encapsulation layer.  don't alert if "next
// layer" is invalid.  If decode fails with this bit set, PacketManager
// will back out to the previous layer.  IMPORTANT:  This bit can ONLY be
// set if the DECODE_ENCAP_LAYER flag was was previously set.
constexpr uint16_t CODEC_UNSURE_ENCAP = 0x0002;

// DO NOT USE THIS LAYER!!  --  use DECODE_ENCAP_LAYER
constexpr uint16_t CODEC_SAVE_LAYER = 0x0004;

// If encapsulation decode fails, back out to this layer This will be
// cleared by PacketManager between decodes This flag automatically sets
// DECODE_ENCAP_LAYER for the next layer (and only the next layer).
constexpr uint16_t CODEC_ENCAP_LAYER = (CODEC_SAVE_LAYER | CODEC_UNSURE_ENCAP );

// used to check ip6 extension order
constexpr uint16_t CODEC_ROUTING_SEEN = 0x0008;

// used by icmp4 for alerting
constexpr uint16_t CODEC_IPOPT_RR_SEEN = 0x0010;

// used by IGMP for alerting
constexpr uint16_t CODEC_IPOPT_RTRALT_SEEN = 0x0020;

// used by IGMP for alerting
constexpr uint16_t CODEC_IPOPT_LEN_THREE = 0x0040;

// used in IPv6 Codec
constexpr uint16_t CODEC_TEREDO_SEEN = 0x0080;

constexpr uint16_t CODEC_STREAM_REBUILT = 0x0100;
constexpr uint16_t CODEC_NON_IP_TUNNEL = 0x0200;

constexpr uint16_t CODEC_IP6_EXT_OOO = 0x0400;
constexpr uint16_t CODEC_IP6_BAD_OPT = 0x0800;

constexpr uint16_t CODEC_ETHER_NEXT = 0x1000;

constexpr uint16_t CODEC_IPOPT_FLAGS = (CODEC_IPOPT_RR_SEEN |
    CODEC_IPOPT_RTRALT_SEEN | CODEC_IPOPT_LEN_THREE);

struct CodecData
{
    /* This section will get reset before every decode() function call */
    ProtocolId next_prot_id;      /* protocol type of the next layer */
    uint16_t lyr_len;           /* The length of the valid part layer */
    uint16_t invalid_bytes;     /* the length of the INVALID part of this layer */

    /* Reset before each decode of packet begins */

    /*  Codec specific fields.  These fields are only relevant to codecs. */
    uint16_t proto_bits;    /* protocols contained within this packet
                                 -- will be propogated to Snort++ Packet struct*/
    uint16_t codec_flags;   /* flags used while decoding */
    uint8_t ip_layer_cnt;

    /*  The following values have junk values after initialization */
    uint8_t ip6_extension_count; /* initialized in cd_ipv6.cc */
    uint8_t curr_ip6_extension;  /* initialized in cd_ipv6.cc */
    IpProtocol ip6_csum_proto;      /* initialized in cd_ipv6.cc.  Used for IPv6 checksums */

    CodecData(ProtocolId init_prot) : next_prot_id(init_prot), lyr_len(0),
        invalid_bytes(0), proto_bits(0), codec_flags(0), ip_layer_cnt(0)
    { }

    bool inline is_cooked() const
    { return codec_flags & CODEC_STREAM_REBUILT; }
};

typedef uint64_t EncodeFlags;
constexpr EncodeFlags ENC_FLAG_FWD = 0x8000000000000000;  // send in forward direction
constexpr EncodeFlags ENC_FLAG_SEQ = 0x4000000000000000;  // VAL bits contain seq adj
constexpr EncodeFlags ENC_FLAG_ID  = 0x2000000000000000;  // use randomized IP ID
constexpr EncodeFlags ENC_FLAG_NET = 0x1000000000000000;  // stop after innermost network (ip4/6)
                                                          // layer
constexpr EncodeFlags ENC_FLAG_DEF = 0x0800000000000000;  // stop before innermost ip4 opts or ip6
                                                          // frag header
constexpr EncodeFlags ENC_FLAG_RAW = 0x0400000000000000;  // don't encode outer eth header (this is
                                                          // raw ip)
constexpr EncodeFlags ENC_FLAG_PAY = 0x0200000000000000;  // set to when a TCP payload is attached
constexpr EncodeFlags ENC_FLAG_PSH = 0x0100000000000000;  // set by PacketManager when TCP should
                                                          // set PUSH flag
constexpr EncodeFlags ENC_FLAG_FIN = 0x0080000000000000;  // set by PacketManager when TCP should
                                                          // set FIN flag
constexpr EncodeFlags ENC_FLAG_TTL = 0x0040000000000000;  // set by PacketManager when TCP should
                                                          // set FIN flag
constexpr EncodeFlags ENC_FLAG_INLINE = 0x0020000000000000;  // set by PacketManager when TCP
                                                             // should set FIN flag
constexpr EncodeFlags ENC_FLAG_RST_CLNT = 0x0010000000000000;  // finish with a client RST packet
constexpr EncodeFlags ENC_FLAG_RST_SRVR = 0x0008000000000000;  // finish with a server RST packet
constexpr EncodeFlags ENC_FLAG_VAL = 0x00000000FFFFFFFF;  // bits for adjusting seq and/or ack

constexpr uint8_t ENC_PROTO_UNSET = 0xFF;

struct SO_PUBLIC EncState
{
    const ip::IpApi& ip_api; /* IP related information. Good for checksums */
    EncodeFlags flags;
    const uint16_t dsize; /* for non-inline, TCP sequence numbers */
    ProtocolId next_ethertype; /*  set the next encoder 'proto' field to this value. */
    IpProtocol next_proto; /*  set the next encoder 'proto' field to this value. */
    const uint8_t ttl;

    EncState(const ip::IpApi& api, EncodeFlags f, IpProtocol pr,
        uint8_t t, uint16_t data_size);

    inline bool next_proto_set() const
    { return (next_proto != IpProtocol::PROTO_NOT_SET); }

    inline bool ethertype_set() const
    { return next_ethertype != ProtocolId::ETHERTYPE_NOT_SET; }

    inline bool forward() const
    { return flags & ENC_FLAG_FWD; }

    uint8_t get_ttl(uint8_t lyr_ttl) const;
};

struct SO_PUBLIC Buffer
{
public:
    Buffer(uint8_t* buf, uint32_t size);

    inline uint8_t* data() const
    { return base; }

    uint32_t size() const
    { return end; }

    inline bool allocate(uint32_t len)
    {
        if ( (end + len) > max_len )
            return false;

        end += len;
        base -= len;
        return true;
    }

    inline void clear()
    { base = base + end; end = 0; off = 0; }

private:
    uint8_t* base; /* start of data */
    uint32_t end;       /* end of data */
    const uint32_t max_len;   /* size of allocation */

public:
    uint32_t off;       /* offset into data */
};

typedef uint8_t UpdateFlags;
constexpr UpdateFlags UPD_COOKED = 0x01;
constexpr UpdateFlags UPD_MODIFIED = 0x02;
constexpr UpdateFlags UPD_RESIZED = 0x04;
constexpr UpdateFlags UPD_REBUILT_FRAG = 0x08;

/*  Codec Class */

class SO_PUBLIC Codec
{
public:
    virtual ~Codec() = default;

    // PKT_MAX = ETHERNET_HEADER_LEN + VLAN_HEADER + ETHERNET_MTU + IP_MAXPACKET

    /* PKT_MAX is sized to ensure that any reassembled packet
     * can accommodate a full datagram at innermost layer
     *
     * ETHERNET_HEADER_LEN == 14
     * VLAN_HEADER == 4
     * ETHERNET_MTU == 1500
     * IP_MAXPACKET ==  65535  FIXIT-L use Packet::max_dsize
     */
    static const uint32_t PKT_MAX = 14 + 4 + 1500 + 65535;

    /*  Codec Initialization */

    // Get the codec's name
    inline const char* get_name() const
    { return name; }
    // Registers this Codec's data link type (as defined by libpcap)
    virtual void get_data_link_type(std::vector<int>&) // FIXIT-M return a vector == efficient in
                                                       // c++11
    { }
    // Register the code's protocol ID's and Ethertypes
    virtual void get_protocol_ids(std::vector<ProtocolId>&)  // FIXIT-M return a vector ==
                                                           // efficient in c++11
    { }

    /*
     * Main decoding function!  Will get called when decoding a packet.
     *
     * PARAMS:
     *      const RawData& = struct containing information about the
     *                      current packet's raw data
     *
     *      CodecData& = Pass information the PacketManager and other
     *              codecs. IMPORTANT FIELDS TO SET IN YOUR CODEC -
     *         next_prot_id   = protocol type of the next layer
     *         lyr_len        = The length of the valid part layer
     *         invalid bytes  = number of invalid bytes between the end of
     *                          the this layer's valid length and the next
     *                           layer. For instance,
     *                          when decoding IP, if there are 20 bytes of
     *                          options but only 12 bytes are valid.
     *
     *                          data.lyr_len = MIN_IP_HEADER_LEN + 12;
     *                          data.invalid_bytes = 8    === 20 - 12
     *
     *      DecodeData& = Data which will be sent to the rest of Snort++.
     *                      contains convenience pointers and information
     *                      about this packet.
     **/
    virtual bool decode(const RawData&, CodecData&, DecodeData&)=0;

    /*
     *  Log this layer's information
     *  PARAMS:
     *          TextLog* = the logger. Defined in "text_log.h"
     *          const uint8_t *raw_pkt = the same data seen during decode
     *          const uint16_t lyr_len = This layer's validated length ==
     *                                   lyr_len set during decode.
     */
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/, const uint16_t /*lyr_len*/)
    { }

    /*
     * Encoding -- active response!!
     *
     * Encode the current packet. Encoding starts with the innermost
     * layer and working outwards.  All encoders MUST call the
     * Buffer.allocate() function before writing to output buffer.
     * PARAMS:
     *        uint8_t* raw_in =  A pointer to the raw input which was decoded.
     *              This is the same pointer which was given to decode().
     *        uint16_t len == the value to which '(CodecData&).lyr_len' was set during decode.
     *              I.e., the validated length of this layer. Some protocols,
     *              like IPv4 (original ipv4 header may contain invalid options
     *              which we don't want to copy) and GTP have dynamic lengths.
     *              So, this parameter ensure the encode() function doesn't
     *              need to revalidate and recalculate the length.
     *        EncState& = The current EncState struct
     *        Buffer& = the packet which will be sent. All inward layers will already
     *              be set.
     *
     * NOTE:  all functions MUST call the Buffer.allocate() function before
     *          manipulating memory.
     */
    virtual bool encode(const uint8_t* const /*raw_in */,
        const uint16_t /*raw_len*/,
        EncState&,
        Buffer&, Flow*)
    { return true; }

    /*
     * Update this layers checksums and length fields.  Used
     * when rebuilding packets and Snort is in inline mode.
     *
     *  updated_len MUST be set to this layers updated length.
     */
    virtual void update(
        const ip::IpApi&,
        const EncodeFlags /*flags*/,
        uint8_t* /*raw_pkt*/,  /* The data associated with the current layer */
        uint16_t lyr_len,  /* This layers previously calculated length */
        uint32_t& updated_len) /* Update!  The length to end of packet */
    { updated_len += lyr_len; }

    // formatter
    virtual void format(bool /*reverse*/, uint8_t* /*raw_pkt*/, DecodeData&)
    { }

protected:
    Codec(const char* s)
    { name = s; }

    // Create an event with the Codec GID
    void codec_event(const CodecData &, CodecSid);
    // Check the Hop and DST IPv6 extension
    bool CheckIPV6HopOptions(const RawData&, CodecData&);
    // NOTE:: data.next_prot_id MUST be set before calling this!!
    void CheckIPv6ExtensionOrder(CodecData&, const IpProtocol);

private:
    const char* name;
};

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

// this is the current version of the api
#define CDAPI_VERSION ((BASE_API_VERSION << 16) | 0)

typedef Codec* (* CdNewFunc)(Module*);
typedef void (* CdDelFunc)(Codec*);
typedef void (* CdAuxFunc)();

struct CodecApi
{
    BaseApi base;

    // these may be nullptr
    CdAuxFunc pinit;  // initialize global plugin data
    CdAuxFunc pterm;  // clean-up pinit()

    CdAuxFunc tinit;  // initialize thread-local plugin data
    CdAuxFunc tterm;  // clean-up tinit()

    // these must be set
    CdNewFunc ctor;   // get eval optional instance data
    CdDelFunc dtor;   // clean up instance data
};
}
#endif /* FRAMEWORK_CODEC_H */

