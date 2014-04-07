/*
**  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
**
*/
// packet_manager.cc author Russ Combs <rucombs@cisco.com>

#include "packet_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <list>
using namespace std;

#include "framework/codec.h"
#include "snort.h"
#include "thread.h"
#include "log/messages.h"
#include "packet_io/sfdaq.h"
#include "protocols/decode.h"

static list<const CodecApi*> s_codecs;

typedef void (*grinder_t)(Packet *, const DAQ_PktHdr_t*, const uint8_t *);

static THREAD_LOCAL grinder_t grinder;

//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------

void PacketManager::add_plugin(const CodecApi* api)
{
    s_codecs.push_back(api);
}

void PacketManager::release_plugins()
{
    s_codecs.clear();
}

void PacketManager::dump_plugins()
{
    Dumper d("Codecs");

    for ( auto* p : s_codecs )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------
// grinder
//-------------------------------------------------------------------------

void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    grinder(p, pkthdr, pkt);
}

int PacketManager::set_grinder(void)
{
    const char* slink = NULL;
    const char* extra = NULL;
    int dlt = DAQ_GetBaseProtocol();

    switch ( dlt )
    {
        case DLT_EN10MB:
            slink = "Ethernet";
            grinder = DecodeEthPkt;
            break;

#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:
            /* loopback and stuff.. you wouldn't perform intrusion detection
             * on it, but it's ok for testing. */
            slink = "LoopBack";
            extra = "Data link layer header parsing for this network type "
                    "isn't implemented yet";
            grinder = DecodeNullPkt;
            break;

        case DLT_RAW:
        case DLT_IPV4:
            slink = "Raw IP4";
            extra = "There's no second layer header available for this datalink";
            grinder = DecodeRawPkt;
            break;

        case DLT_IPV6:
            slink = "Raw IP6";
            extra = "There's no second layer header available for this datalink";
            grinder = DecodeRawPkt6;
            break;

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
            slink = "I4L-ip";
            grinder = DecodeEthPkt;
            break;
#endif

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
            slink = "I4L-cisco-h";
            grinder = DecodeI4LCiscoIPPkt;
            break;
#endif

        case DLT_PPP:
            slink = "PPP";
            extra = "Second layer header parsing for this datalink "
                    "isn't implemented yet";
            grinder = DecodePppPkt;
            break;

#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:
            // you need the I4L modified version of libpcap to get this stuff
            // working
            slink = "I4L-rawip";
            grinder = DecodeI4LRawIPPkt;
            break;
#endif

#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            slink = "IEEE 802.11";
            grinder = DecodeIEEE80211Pkt;
            break;
#endif
#ifdef DLT_ENC
        case DLT_ENC:
            slink = "Encapsulated data";
            grinder = DecodeEncPkt;
            break;

#else
        case 13:
#endif /* DLT_ENC */
        case DLT_IEEE802:
            slink = "Token Ring";
            grinder = DecodeTRPkt;
            break;

        case DLT_FDDI:
            slink = "FDDI";
            grinder = DecodeFDDIPkt;
            break;

#ifdef DLT_CHDLC
        case DLT_CHDLC:
            slink = "Cisco HDLC";
            grinder = DecodeChdlcPkt;
            break;
#endif

        case DLT_SLIP:
            slink = "SLIP";
            extra = "Second layer header parsing for this datalink "
                    "isn't implemented yet\n";
            grinder = DecodeSlipPkt;
            break;

#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
            slink = "PPP Serial";
            extra = "Second layer header parsing for this datalink "
                    " isn't implemented yet";
            grinder = DecodePppSerialPkt;
            break;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            slink = "Linux SLL";
            grinder = DecodeLinuxSLLPkt;
            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
            slink = "OpenBSD PF log";
            grinder = DecodePflog;
            break;
#endif

#ifdef DLT_OLDPFLOG
        case DLT_OLDPFLOG:
            slink = "Old OpenBSD PF log";
            grinder = DecodeOldPflog;
            break;
#endif
#endif  // NO_NON_ETHER_DECODER

        default:
            /* oops, don't know how to handle this one */
            FatalError("Cannot decode data link type %d\n", dlt);
            break;
    }

    if ( !ScReadMode() || ScPcapShow() )
    {
        LogMessage("Decoding %s\n", slink);
    }
    if (extra && ScOutputDataLink())
    {
        LogMessage("%s\n", extra);
        snort_conf->output_flags &= ~OUTPUT_FLAG__SHOW_DATA_LINK;
    }
    return 0;
}

