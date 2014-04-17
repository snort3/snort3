/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

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
#include "time/profiler.h"
#include "mempool/mempool.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "snort.h"
#include "packet_io/active.h"
#include "utils/stats.h"
#include "codecs/decode_module.h"

#if 0
    // the empty bracket initializes the array to false
//static std::array<bool, DECODE_INDEX_MAX> CodecEvents::decodeRuleEnabled() = {};
static const uint16_t DECODE_INDEX_MAX = 0xFFFF; // == 2^16 - 1

THREAD_LOCAL tSfActionQueue* decoderActionQ;
THREAD_LOCAL MemPool decoderAlertMemPool;

static THREAD_LOCAL PegCount bad_ttl = 0;



void CodecEvents::queueDecoderEvent(
    unsigned int gid,
    unsigned int sid,
    unsigned int rev,
    unsigned int classification,
    unsigned int pri,
    const char *msg,
    void *rule_info)
{
    MemBucket *alertBucket;
    EventNode *en;
    int ret;

    alertBucket = (MemBucket *)mempool_alloc(&decoderAlertMemPool);
    if(!alertBucket)
        return;

    en = (EventNode *)alertBucket->data;
    en->gid = gid;
    en->sid = sid;
    en->rev = rev;
    en->classification = classification;
    en->priority = pri;
    en->msg = msg;
    en->rule_info = rule_info;

    ret = sfActionQueueAdd( decoderActionQ, execDecoderEvent, alertBucket);
    if (ret == -1)
    {
        ErrorMessage("Could not add event to decoderActionQ\n");
        mempool_free(&decoderAlertMemPool, alertBucket);
    }
}


void CodecEvents::execDecoderEvent(void *data)
{
    MemBucket *alertBucket = (MemBucket *)data;
    EventNode *en = (EventNode *)alertBucket->data;

    if ( ScDecoderAlerts() )
    {
        SnortEventqAdd(en->gid, en->sid, en->rev, en->classification,
            en->priority, en->msg, en->rule_info);
    }
    mempool_free(&decoderAlertMemPool, alertBucket);
}




void CodecEvents::DecoderOptEvent (
    Packet *p, int sid, const char *str, void_callback_f callback )
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%s\n", str);

    queueDecoderEvent(GENERATOR_SNORT_DECODE, sid, 1,
        DECODE_CLASS, 3, str, 0);

    queue_exec_drop(callback, p);
}




bool CodecEvents::event_enabled(int sid)
{
    return true;
}



void CodecEvents::queue_exec_drop(
    void_callback_f callback, Packet* p)
{
    int ret = sfActionQueueAdd( decoderActionQ, callback, (void*)p);
    if (ret == -1)
    {
        ErrorMessage("Could not add drop event to decoderActionQ\n");
    }
}


void CodecEvents::decoder_init(unsigned max)
{
    decoderActionQ = sfActionQueueInit(max);

    if (mempool_init(&decoderAlertMemPool, max, sizeof(EventNode)) != 0)
    {
        FatalError("Could not initialize decoder action queue memory pool.\n");
    }
}

void CodecEvents::decoder_term()
{
    if (decoderActionQ != NULL)
    {
        sfActionQueueDestroy (decoderActionQ);
        mempool_destroy (&decoderAlertMemPool);
        decoderActionQ = NULL;
        memset(&decoderAlertMemPool, 0, sizeof(decoderAlertMemPool));
    }
}

void CodecEvents::decoder_exec()
{
    sfActionQueueExecAll(decoderActionQ);
}

#endif




//****************************************************************************************************88




void CodecEvents::decoder_event (Packet *p, int sid)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);
}

void CodecEvents::execTcpChksmDrop (Packet*)
{
    if( ScInlineMode() && ScTcpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (TCP checksum)\n"););
        Active_DropPacket();
    }
}

void CodecEvents::exec_udp_chksm_drop (Packet *)
{
    if( ScInlineMode() && ScUdpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (UDP checksum)\n"););
        Active_DropPacket();
    }
}


void CodecEvents::exec_ip_chksm_drop (Packet*)
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

void CodecEvents::exec_hop_drop (Packet* p, int sid)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);

    if ( ScNormalDrop(NORM_IP6_TTL) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
           "Dropping bad packet (IP6 hop limit)\n"););
        p->error_flags |= PKT_ERR_BAD_TTL;
        Active_DropPacket();
//        dc.bad_ttl++;
    }
}



void CodecEvents::exec_ttl_drop (Packet *p, int sid)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);

    if ( ScNormalDrop(NORM_IP4_TTL) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
           "Dropping bad packet (IP4 TTL)\n"););
        p->error_flags |= PKT_ERR_BAD_TTL;
        Active_DropPacket();
//        dc.bad_ttl++;
    }
}


void CodecEvents::execIcmpChksmDrop (void*)
{
    if( ScInlineMode() && ScIcmpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (ICMP checksum)\n"););
        Active_DropPacket();
    }
}

void CodecEvents::decoder_alert_encapsulated(
    Packet *p, int sid, const uint8_t *pkt, uint32_t len)
{
    DecoderEvent(p, sid);

    p->data = pkt;
    p->dsize = (uint16_t)len;

    p->greh = NULL;
}


//-----------------

int CodecEvents::ScNormalDrop (NormFlags nf)
{
    return !Normalize_IsEnabled(snort_conf, nf);
}


