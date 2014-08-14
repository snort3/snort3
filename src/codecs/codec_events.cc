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

#include "codecs/codec_events.h"
#include "snort.h"
#include "packet_io/active.h"

void codec_events::exec_udp_chksm_drop (const Packet* const/*p*/)
{
    if( ScInlineMode() && ScUdpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (UDP checksum)\n"););
        Active_DropPacket();
    }
}

void codec_events::exec_tcp_chksm_drop (const Packet* const /*p*/)
{
    if( ScInlineMode() && ScTcpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (TCP checksum)\n"););
        Active_DropPacket();
    }
}

void codec_events::decoder_event(const Packet* const p, CodecSid sid)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);
}

void codec_events::exec_ip_chksm_drop (const Packet* const /*p*/)
{
    // TBD only set policy csum drop if policy inline
    // and delete this inline mode check
    if( ScInlineMode() && ScIpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (IP checksum)\n"););
        Active_DropPacket();
    }
}

void codec_events::exec_icmp_chksm_drop (const Packet* const /*p*/)
{
    if( ScInlineMode() && ScIcmpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (ICMP checksum)\n"););
        Active_DropPacket();
    }
}

void codec_events::decoder_alert_encapsulated(Packet* const p,
                                              CodecSid sid,
                                              const uint8_t *pkt,
                                              uint32_t len)
{
    decoder_event(p, sid);

    p->data = pkt;
    p->dsize = (uint16_t)len;
}

