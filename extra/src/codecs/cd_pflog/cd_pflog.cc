//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

#include <net/if.h>
#include <sfbpf_dlt.h>

#include "framework/codec.h"

#define PFLOG_NAME "pflog"
#define PFLOG_HELP_STR "support for OpenBSD PF log"

#define PFLOG_HELP ADD_DLT(PFLOG_HELP_STR, DLT_PFLOG)

namespace
{
/*
 * Snort supports 3 versions of the OpenBSD pflog header:
 *
 * Pflog1_Hdr:  CVS = 1.3,  DLT_OLD_PFLOG = 17,  Length = 28
 * Pflog2_Hdr:  CVS = 1.8,  DLT_PFLOG     = 117, Length = 48
 * Pflog3_Hdr:  CVS = 1.12, DLT_PFLOG     = 117, Length = 64
 * Pflog3_Hdr:  CVS = 1.172, DLT_PFLOG     = 117, Length = 100
 *
 * Since they have the same DLT, Pflog{2,3}Hdr are distinguished
 * by their actual length.  The minimum required length excludes
 * padding.
 */
/* Old OpenBSD pf firewall pflog0 header
 * (information from pf source in kernel)
 * the rule, reason, and action codes tell why the firewall dropped it -fleck
 */

class PflogCodec : public Codec
{
public:
    PflogCodec() : Codec(PFLOG_NAME) { }
    ~PflogCodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_data_link_type(std::vector<int>&) override;
};

struct Pflog1Hdr
{
    uint32_t af;
    char intf[IFNAMSIZ];
    int16_t rule;
    uint16_t reason;
    uint16_t action;
    uint16_t dir;
};

#define PFLOG1_HDRLEN (sizeof(struct _Pflog1_hdr))

/*
 * Note that on OpenBSD, af type is sa_family_t. On Linux, that's an unsigned
 * short, but on OpenBSD, that's a uint8_t, so we should explicitly use uint8_t
 * here.  - ronaldo
 */

#define PFLOG_RULELEN 16
#define PFLOG_PADLEN  3

struct Pflog2Hdr
{
    int8_t length;
    uint8_t af;
    uint8_t action;
    uint8_t reason;
    char ifname[IFNAMSIZ];
    char ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint8_t dir;
    uint8_t pad[PFLOG_PADLEN];
};

#define PFLOG2_HDRLEN (sizeof(Pflog2Hdr))
#define PFLOG2_HDRMIN (PFLOG2_HDRLEN - PFLOG_PADLEN)

struct Pflog3Hdr
{
    int8_t length;
    uint8_t af;
    uint8_t action;
    uint8_t reason;
    char ifname[IFNAMSIZ];
    char ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    uint32_t rule_uid;
    uint32_t rule_pid;
    uint8_t dir;
    uint8_t pad[PFLOG_PADLEN];
};

#define PFLOG3_HDRLEN (sizeof(Pflog3Hdr))
#define PFLOG3_HDRMIN (PFLOG3_HDRLEN - PFLOG_PADLEN)

struct Pflog4Hdr
{
    uint8_t length;
    uint8_t af;
    uint8_t action;
    uint8_t reason;
    char ifname[IFNAMSIZ];
    char ruleset[PFLOG_RULELEN];
    uint32_t rulenr;
    uint32_t subrulenr;
    uint32_t uid;
    uint32_t pid;
    uint32_t rule_uid;
    uint32_t rule_pid;
    uint8_t dir;
    uint8_t rewritten;
    uint8_t pad[2];
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint16_t sport;
    uint16_t dport;
};

#define PFLOG4_HDRLEN sizeof(struct Pflog4Hdr)
#define PFLOG4_HDRMIN sizeof(struct Pflog4Hdr)
} // namespace

void PflogCodec::get_data_link_type(std::vector<int>& v)
{ v.push_back(DLT_PFLOG); }

bool PflogCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    const uint32_t cap_len = raw.len;
    uint8_t af, pflen;
    uint32_t hlen;
    uint32_t padlen = PFLOG_PADLEN;

    if (cap_len < PFLOG2_HDRMIN)
        return false;

    /* lay the pf header structure over the packet data */
    switch (*((uint8_t*)raw.data))
    {
    case PFLOG2_HDRMIN:
    {
        const Pflog2Hdr* const pf2h =
            reinterpret_cast<const Pflog2Hdr*>(raw.data);
        pflen = pf2h->length;
        hlen = PFLOG2_HDRLEN;
        af = pf2h->af;
        break;
    }
    case PFLOG3_HDRMIN:
    {
        const Pflog3Hdr* const pf3h =
            reinterpret_cast<const Pflog3Hdr*>(raw.data);
        pflen = pf3h->length;
        hlen = PFLOG3_HDRLEN;
        af = pf3h->af;
        break;
    }
    case PFLOG4_HDRMIN:
    {
        const Pflog4Hdr* const pf4h =
            reinterpret_cast<const Pflog4Hdr*>(raw.data);
        pflen = pf4h->length;
        hlen = PFLOG4_HDRLEN;
        af = pf4h->af;
        padlen = sizeof(pf4h->pad);
        break;
    }
    default:
        return false;
    }

    /* now that we know a little more, do a little more validation */
    if (cap_len < hlen)
        return false;

    /* note that the pflen may exclude the padding which is always present */
    if (pflen < hlen - padlen || pflen > hlen)
        return false;

    /* check the network type - should only be AF_INET or AF_INET6 */
    switch (af)
    {
    case AF_INET:       /* IPv4 */
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV4;
        break;

    case AF_INET6:      /* IPv6 */
        codec.next_prot_id = ProtocolId::ETHERTYPE_IPV6;
        break;

    default:
        /* FIXIT-L add decoder drop event for unknown pflog network type
         * To my knowledge, pflog devices can only
         * pass IP and IP6 packets. -fleck
         */
        break;
    }

    codec.lyr_len = hlen;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new PflogCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi pflog_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        PFLOG_NAME,
        PFLOG_HELP,
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    nullptr, // ginit
    nullptr, // gterm
    nullptr, // tinit
    nullptr, // tterm
    ctor,
    dtor,
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pflog_api.base,
    nullptr
};
