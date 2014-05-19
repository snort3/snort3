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

#ifndef CODEC_EVENTS_H
#define CODEC_EVENTS_H

#include <array>

// included for DECODE_INDEX_MAX
#include "detection/generators.h"
//#include "utils/sfActionQueue.h"
#include "network_inspectors/normalize/normalize.h"
#include "protocols/packet.h"
#include "time/profiler.h"
#include "codecs/decode_module.h"

namespace codec_events
{

    void exec_ip_chksm_drop(Packet*);
    void exec_udp_chksm_drop (Packet *);
    void exec_tcp_chksm_drop (Packet*);
    void exec_hop_drop(Packet* p, int sid);
    void exec_ttl_drop (Packet *data, int sid);
    void exec_icmp_chksm_drop (Packet*);

    void decoder_event (Packet *, int);
    void decoder_alert_encapsulated(
        Packet *p, int sid, const uint8_t *pkt, uint32_t len);

} //namespace codec_events


#endif

