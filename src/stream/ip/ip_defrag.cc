//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

/*
 * ip_defrag.cc is derived from frag3.c by Martin Roesch <roesch@sourcefire.com>
 */

/*
 * Notes:
 * Frag3 sports the following improvements over frag2:
 *  - engine-based IP defragmentation, harder to evade
 *  - 8 Anomaly detection event types
 *  - Two separate memory management strategies to tailor
 *    performance for specific environments
 *  - Up to 250% faster than frag2.
 *
 *  The mechanism for processing frags is based on the Linux IP stack
 *  implementation of IP defragmentation with proper amounts of paranoia
 *  and an IDS perspective applied.  Some of this code was derived from
 *  frag2 originally, but it's basically unrecognizable if you compare
 *  it to frag2 IMO.
 *
 *  I switched from using the UBI libs to using sfxhash and linked lists for
 *  fragment management because I suspected that the management code was
 *  the cause of performance issues that we were observing at Sourcefire
 *  in certain customer situations.  Splay trees are cool and really hard
 *  to screw with from an attack perspective, but they also incur a lot
 *  of overhead for managing the tree and lose the order of the fragments in
 *  the FragTracker's fraglist, so I dropped them.  Originally the
 *  frag3 code was just supposed to migrate away from the splay tree system
 *  that I was using in frag2, but I figured since I was doing the work to
 *  pull out the splay trees I may as well solve some of the other problems
 *  we were seeing.
 *
 *  Initial performance testing that I've done shows that frag3 can be as much
 *  as 250% faster than frag2, but we still need to do more testing and
 *  optimization, we may be able to squeeze out some more performance.
 *
 *  Frag3 is also capable of performing "engine-based" IP defragmentation.
 *  What this means practically is that frag3 can model the IP stack of a
 *  engine on the network to avoid Ptacek-Newsham evasions of the IDS through
 *  sensor/engine desynchronization.  In terms of implementation, this is
 *  reflected by passing a "engine" into the defragmentation engine that has
 *  a specific configuration for a specific engine type.  Windows can put
 *  fragments back together differently than Linux/BSD/etc, so we model that
 *  inside frag3 so we can't be evaded.
 */

/*  I N C L U D E S  ************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ip_defrag.h"

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "profiler/profiler_defs.h"
#include "protocols/ipv4_options.h"
#include "time/timersub.h"
#include "utils/safec.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "ip_session.h"
#include "stream_ip.h"

using namespace snort;

/*  D E F I N E S  **************************************************/

/* flags for the FragTracker->frag_flags field */
#define FRAG_GOT_FIRST      0x00000001
#define FRAG_GOT_LAST       0x00000002
#define FRAG_REBUILT        0x00000004
#define FRAG_BAD            0x00000008
#define FRAG_NO_BSD_VULN    0x00000010
#define FRAG_DROP_FRAGMENTS 0x00000020

/* return values for insert() */
#define FRAG_INSERT_OK          0
#define FRAG_INSERT_FAILED      1
//#define FRAG_INSERT_REJECTED    2
#define FRAG_INSERT_TIMEOUT     3
#define FRAG_INSERT_ATTACK      4
#define FRAG_INSERT_ANOMALY     5
#define FRAG_INSERT_TTL         6
#define FRAG_INSERT_OVERLAP_LIMIT  7

/* return values for FragCheckFirstLast() */
#define FRAG_FIRSTLAST_OK       0
#define FRAG_LAST_DUPLICATE     1
#define FRAG_LAST_OFFSET_ADJUST 2

/*  D A T A   S T R U C T U R E S  **********************************/


struct Fragment
{
    Fragment(uint16_t flen, const uint8_t* fptr, int ord)
    { init(flen, fptr, ord); }

    Fragment(Fragment* other, int ord)
    {
        init(other->flen, other->fptr, ord);
        data = fptr + (other->data - other->fptr);
        size = other->size;
        offset = other->offset;
        last = other->last;
    }

    ~Fragment()
    {
        delete[] fptr;
        ip_stats.nodes_released++;
    }

    uint8_t* data = nullptr;    /* ptr to adjusted start position */
    uint16_t size = 0;          /* adjusted frag size */
    uint16_t offset = 0;        /* adjusted offset position */

    uint8_t* fptr = nullptr;    /* free pointer */
    uint16_t flen = 0;          /* free len, unneeded? */

    Fragment* prev = nullptr;
    Fragment* next = nullptr;

    int ord = 0;
    char last = 0;

private:
    inline void init(uint16_t flen, const uint8_t* fptr, int ord)
    {
        assert(flen > 0);

        this->flen = flen;
        this->fptr = new uint8_t[flen];
        this->ord = ord;

        memcpy(this->fptr, fptr, flen);

        ip_stats.nodes_created++;
    }
};

/*  G L O B A L S  **************************************************/

/* enum for policy names */
static const char* const frag_policy_names[] =
{
    "no policy",
    "FIRST",
    "LINUX",
    "BSD",
    "BSD_RIGHT",
    "LAST",
    "WINDOWS",
    "SOLARIS"
};

THREAD_LOCAL ProfileStats fragPerfStats;
THREAD_LOCAL ProfileStats fragInsertPerfStats;
THREAD_LOCAL ProfileStats fragRebuildPerfStats;

static void FragPrintEngineConfig(FragEngine* engine)
{
    LogMessage("Defrag engine config:\n");
    LogMessage("    engine-based policy: %s\n",
        frag_policy_names[engine->frag_policy]);
    LogMessage("    Fragment timeout: %d seconds\n",
        engine->frag_timeout);
    LogMessage("    Fragment min_ttl:   %d\n", engine->min_ttl);

    LogMessage("    Max frags: %d\n", engine->max_frags);
    LogMessage("    Max overlaps:     %d\n",
        engine->max_overlaps);
    LogMessage("    Min fragment Length:     %d\n",
        engine->min_fragment_length);
#ifdef REG_TEST
    LogMessage("    FragTracker Size: %zu\n", sizeof(FragTracker));
#endif
}

static inline void EventAnomIpOpts(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_IPOPTIONS);
    ip_stats.alerts++;
}

static inline void EventAttackTeardrop(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_TEARDROP);
    ip_stats.alerts++;
}

static inline void EventTinyFragments(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_TINY_FRAGMENT);
    ip_stats.alerts++;
}

static inline void EventExcessiveOverlap(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_EXCESSIVE_OVERLAP);
    ip_stats.alerts++;
}

static inline void EventAnomShortFrag(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_SHORT_FRAG);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomOversize(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_ANOMALY_OVERSIZE);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomZeroFrag(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_ANOMALY_ZERO);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomBadsizeLg(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_ANOMALY_BADSIZE_LG);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomBadsizeSm(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_ANOMALY_BADSIZE_SM);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomOverlap(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_ANOMALY_OVLP);
    ip_stats.alerts++;
    ip_stats.anomalies++;
}

static inline void EventAnomMinTtl(FragEngine*)
{
    DetectionEngine::queue_event(GID_DEFRAG, DEFRAG_MIN_TTL_EVASION);
    ip_stats.alerts++;
}

static inline bool frag_timed_out(
    const timeval* current_time, const timeval* start_time, FragEngine* engine)
{
    struct timeval tv_diff;
    TIMERSUB(current_time, start_time, &tv_diff);

    if (tv_diff.tv_sec >= (int)engine->frag_timeout)
        return true;

    return false;
}

/**
 * Check to see if we've got the first or last fragment on a FragTracker and
 * set the appropriate frag_flags
 *
 * @param p Packet to get the info from
 * @param ft FragTracker to set the flags on
 *
 * @return none
 */
static inline int FragCheckFirstLast(
    const Packet* const p,
    FragTracker* ft,
    const uint16_t frag_offset)
{
    uint16_t fragLength;
    int retVal = FRAG_FIRSTLAST_OK;
    uint16_t endOfThisFrag;

    /* set the frag flag if this is the first fragment */
    if ((p->ptrs.decode_flags & DECODE_MF) && frag_offset == 0)
    {
        ft->frag_flags |= FRAG_GOT_FIRST;

        trace_log(stream_ip, "Got first frag\n");
    }
    else if ((!(p->ptrs.decode_flags & DECODE_MF)) && (frag_offset > 0)) /* set for last frag too
                                                                           */
    {
        /* Use the actual length here because packet may have been
         * truncated.  Don't want to try to copy more than we actually
         * captured. Use dsize as the frag length since it is distance
         * between the last succesfully decoded layer (which is ip6_frag
         *  or ipv4) and the end of packet, */
        fragLength = p->dsize;
        endOfThisFrag = frag_offset + fragLength;

        if (ft->frag_flags & FRAG_GOT_LAST)
        {
            trace_log(stream_ip, "Got last frag again!\n");
            switch (ft->frag_policy)
            {
            case FRAG_POLICY_BSD:
            case FRAG_POLICY_LINUX:
            case FRAG_POLICY_BSD_RIGHT:
            case FRAG_POLICY_LAST:
            case FRAG_POLICY_WINDOWS:
            case FRAG_POLICY_FIRST:
                if (ft->calculated_size > endOfThisFrag)
                {
                    /* Already have a 'last frag' with a higher
                     * end point.  Leave it as is.
                     *
                     * Some OS's do not respond at all -- we'll
                     * still try to rebuild anyway in that case,
                     * because there is really something wrong
                     * and we should look at it.
                     */
                    retVal = FRAG_LAST_DUPLICATE;
                }
                break;
            case FRAG_POLICY_SOLARIS:
                if (ft->calculated_size > endOfThisFrag)
                {
                    /* Already have a 'last frag' with a higher
                     * end point.  Leave it as is.
                     *
                     * Some OS's do not respond at all -- we'll
                     * still try to rebuild anyway in that case,
                     * because there is really something wrong
                     * and we should look at it.
                     */
                    retVal = FRAG_LAST_DUPLICATE;
                }
                else
                {
                    /* Solaris does some weird stuff here... */
                    /* Usually, Solaris takes the higher end point.
                     * But in one strange case (when it hasn't seen
                     * any frags beyond the existing last frag), it
                     * actually appends that new last frag to the
                     * end of the previous last frag, regardless of
                     * the offset.  Effectively, it adjusts the
                     * offset of the new last frag to immediately
                     * after the existing last frag.
                     */
                    /* XXX: how to handle that case? punt?  */
                    retVal = FRAG_LAST_OFFSET_ADJUST;
                }
                break;
            }
        }

        ft->frag_flags |= FRAG_GOT_LAST;

        /*
         * If this is the last frag (and we don't have a frag that already
         * extends beyond this one), set the size that we're expecting.
         */
        if ((ft->calculated_size < endOfThisFrag) &&
            (retVal != FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = endOfThisFrag;

            trace_logf(stream_ip, "Got last frag, Bytes: %u, "
                "Calculated size: %u\n",
                ft->frag_bytes,
                ft->calculated_size);
        }
    }

    if (frag_offset != 0)
    {
        ft->frag_flags |= FRAG_NO_BSD_VULN;
    }

    trace_logf(stream_ip, "Frag Status: %s:%s\n",
        ft->frag_flags&FRAG_GOT_FIRST ? "FIRST" : "No FIRST",
        ft->frag_flags&FRAG_GOT_LAST ? "LAST" : "No LAST");
    return retVal;
}

/**
 * Handle IP Options in fragmented packets.
 *
 * @param ft Current frag tracker for this packet
 * @param p Current packet to check for options
 * @param engine In case we get an anomaly
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
static int FragHandleIPOptions(
    FragTracker* ft,
    const Packet* const p,
    const uint16_t frag_offset)
{
    const uint16_t ip_options_len = p->ptrs.ip_api.get_ip_opt_len();

    if (frag_offset == 0)
    {
        /*
         * This is the first packet.  If it has IP options,
         * save them off, so we can set them on the reassembled packet.
         */
        if (ip_options_len)
        {
            if (ft->ip_options_data)
            {
                /* Already seen 0 offset packet and copied some IP options */
                if ((ft->frag_flags & FRAG_GOT_FIRST)
                    && (ft->ip_options_len != ip_options_len))
                {
                    EventAnomIpOpts(ft->engine);
                }
            }
            else
            {
                /* Allocate and copy in the options */
                ft->ip_options_data = (uint8_t*)snort_calloc(ip_options_len);
                memcpy(ft->ip_options_data, p->ptrs.ip_api.get_ip_opt_data(), ip_options_len);
                ft->ip_options_len = ip_options_len;
            }
        }
    }
    else
    {
        /* check that options match those from other non-offset 0 packets */

        /* XXX: could check each individual option here, but that
         * would be performance ugly.  So, we'll just check that the
         * option sizes match.  Alert if invalid, but still include in
         * reassembly.
         */
        if (ft->copied_ip_options_len)
        {
            if (ft->copied_ip_options_len != ip_options_len)
            {
                EventAnomIpOpts(ft->engine);
            }
        }
        else
        {
            ft->copied_ip_options_len = ip_options_len;

            ip::IpOptionIterator iter(p->ptrs.ip_api.get_ip4h(), p);

            for (const ip::IpOptions& opt : iter)
            {
                /* Is the high bit set?  If not, weird anomaly. */
                if ( !(static_cast<uint8_t>(opt.code) & 0x80) &&
                    (opt.code != ip::IPOptionCodes::EOL) )
                {
                    EventAnomIpOpts(ft->engine);
                }
            }
        }
    }
    return 1;
}

/** checks for tiny fragments and raises appropriate alarm
 *
 * @param p Current packet to insert
 * @param ft FragTracker to hold the packet
 * @param engine engine of the current engine for engine-based defrag info
 *
 * @returns 1 if tiny fragment was detected, 0 otherwise
 */
static inline int checkTinyFragments(
    FragEngine* engine,
    const Packet* const p,
    unsigned int trimmedLength)
{
    //Snort may need to raise a separate event if
    //only trimmed length is tiny.
    if (p->ptrs.decode_flags & DECODE_MF)
    {
        ///detect tiny fragments before processing overlaps.
        if (engine->min_fragment_length)
        {
            if (p->dsize <= engine->min_fragment_length)
            {
                trace_logf(stream_ip,
                    "Frag: Received fragment size(%d) is not more than configured min_fragment_length (%u)\n",
                    p->dsize, engine->min_fragment_length);
                EventTinyFragments(engine);
                return 1;
            }

            ///detect tiny fragments after processing overlaps.
            if (trimmedLength <= engine->min_fragment_length)
            {
                trace_logf(stream_ip,
                    "Frag: # of New octets in Received fragment(%u) is not more than configured min_fragment_length (%u)\n",
                    trimmedLength, engine->min_fragment_length);
                EventTinyFragments(engine);
                return 1;
            }
        }
    }

    return 0;
}

/**
 * Check to see if a FragTracker has met all of its completion criteria
 *
 * @param ft FragTracker to check
 *
 * @return status
 * @retval 1 If the FragTracker is ready to be rebuilt
 * @retval 0 If the FragTracker hasn't fulfilled its completion criteria
 */
static inline int FragIsComplete(FragTracker* ft)
{
    trace_log(stream_ip,
        "[$] Checking completion criteria\n");

    /*
     * check to see if the first and last frags have arrived
     */
    if ((ft->frag_flags & FRAG_GOT_FIRST) &&
        (ft->frag_flags & FRAG_GOT_LAST))
    {
        trace_log(stream_ip,
            "   Got First and Last frags\n");

        /*
         * if we've accumulated enough data to match the calculated size
         * of the defragged packet, return 1
         */
        if (ft->frag_bytes == ft->calculated_size)
        {
            trace_log(stream_ip,
                "   [!] frag_bytes = calculated_size!\n");

            ip_stats.trackers_completed++;

            return 1;
        }

        if (ft->frag_bytes > ft->calculated_size)
        {
            trace_log(stream_ip,
                "   [!] frag_bytes > calculated_size!\n");

            ip_stats.trackers_completed++;

            return 1;
        }

        trace_logf(stream_ip,
            "   Calc size (%u) != frag bytes (%u)\n",
            ft->calculated_size, ft->frag_bytes);

        /*
         * no dice
         */
        return 0;
    }

    trace_logf(stream_ip,
        "   Missing First or Last frags (frag_flags: 0x%X)\n",
        ft->frag_flags);

    return 0;
}

/*
 * Reassemble the packet from the data in the FragTracker and reinject into
 * Snort's packet analysis system
 */
static void FragRebuild(FragTracker* ft, Packet* p)
{
    DeepProfile profile(fragRebuildPerfStats);
    size_t offset = 0;

    Packet* dpkt = DetectionEngine::set_next_packet(p);
    PacketManager::encode_format(ENC_FLAG_DEF|ENC_FLAG_FWD, p, dpkt, PSEUDO_PKT_IP);

    // the encoder ensures enough space for a maximum datagram
    uint8_t* rebuild_ptr = const_cast<uint8_t*>(dpkt->data);

    if (p->ptrs.ip_api.is_ip4())
    {
        ip::IP4Hdr* iph = const_cast<ip::IP4Hdr*>(dpkt->ptrs.ip_api.get_ip4h());

        /*
         * if there are IP options, copy those in as well
         * these are for the inner IP...
         */
        if (ft->ip_options_data && ft->ip_options_len)
        {
            /* Adjust the IP header size in pseudo packet for the new length */
            uint8_t new_ip_hlen = ip::IP4_HEADER_LEN + ft->ip_options_len;

            trace_logf(stream_ip,
                "Adjusting IP Header to %d bytes\n",
                new_ip_hlen);
            iph->set_hlen(new_ip_hlen >> 2);

            memcpy_s(rebuild_ptr, IP_MAXPACKET, ft->ip_options_data, ft->ip_options_len);
            rebuild_ptr += ft->ip_options_len;
            offset += ft->ip_options_len;
        }
        else if (ft->copied_ip_options_len)
        {
            /* XXX: should we log a warning here?  there were IP options
             * copied across all fragments, EXCEPT the offset 0 fragment.
             */
        }

        /*
         * clear the packet fragment fields
         */
        iph->ip_off = 0x0000;
        dpkt->ptrs.decode_flags &= ~DECODE_FRAG;

        trace_log(stream_ip,
            "[^^] Walking fraglist:\n");
    }

    /*
     * walk the fragment list and rebuild the packet
     */
    for ( Fragment* frag = ft->fraglist; frag; frag = frag->next )
    {
        trace_logf(stream_ip,
            "   frag: %p\n"
            "   frag->data: %p\n"
            "   frag->offset: %d\n"
            "   frag->size: %d\n"
            "   frag->prev: %p\n"
            "   frag->next: %p\n",
            (void*) frag, frag->data, frag->offset,
            frag->size, (void*) frag->prev, (void*) frag->next);

        /*
         * We somehow got a frag that had data beyond the calculated
         * end. Don't want to include it.
         */
        if ((frag->offset + frag->size) > (uint16_t)ft->calculated_size)
            continue;

        /*
         * try to avoid buffer overflows...
         */
        if (frag->size)
        {
            if (frag->size > IP_MAXPACKET - frag->offset - offset)
            {
                ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
                return;
            }

            memcpy_s(rebuild_ptr + frag->offset,
                IP_MAXPACKET - frag->offset - offset, frag->data, frag->size);
        }
    }

    if (p->ptrs.ip_api.is_ip4())
    {
        /*
         * tell the rest of the system that this is a rebuilt fragment
         */
        dpkt->packet_flags |= PKT_REBUILT_FRAG;
        dpkt->ptrs.decode_flags &= ~DECODE_FRAG;
        dpkt->dsize = (uint16_t)ft->calculated_size;

        PacketManager::encode_update(dpkt);
    }
    else /* Inner/only is IP6 */
    {
        if ( !p->is_ip6() )
        {
            /*XXX: Log message, failed to copy */
            ft->frag_flags = ft->frag_flags | FRAG_REBUILT;
            return;
        }

        const Layer& lyr = dpkt->layers[dpkt->num_layers-1];

        if ((lyr.prot_id == ProtocolId::ETHERTYPE_IPV6) || (lyr.prot_id == ProtocolId::IPV6))
        {
            ip::IP6Hdr* const rawHdr =
                const_cast<ip::IP6Hdr*>(dpkt->ptrs.ip_api.get_ip6h());
            rawHdr->ip6_next = ft->ip_proto;
        }
        else
        {
            ip::IP6Extension* const ip6_ext = const_cast<ip::IP6Extension*>(
                reinterpret_cast<const ip::IP6Extension*>(lyr.start));

            ip6_ext->ip6e_nxt = ft->ip_proto;
        }

        dpkt->dsize = (uint16_t)ft->calculated_size;
        PacketManager::encode_update(dpkt);
    }

    /* Rebuild is complete */

    /*
     * process the packet through the detection engine
     */
    trace_log(stream_ip,
        "Processing rebuilt packet:\n");

    ip_stats.reassembles++;
    ip_stats.reassembled_bytes += dpkt->pkth->caplen;

#if defined(DEBUG_FRAG_EX) && defined(DEBUG_MSGS)
    /*
     * Note, that this won't print out the IP Options or any other
     * data that is established when the packet is decoded.
     */
    if ( stream_ip.enabled(1) )
        LogIPPkt(dpkt);
#endif

    DetectionEngine de;
    de.set_encode_packet(p);
    snort::Snort::process_packet(dpkt, dpkt->pkth, dpkt->pkt, true);
    de.set_encode_packet(nullptr);

    trace_log(stream_ip, "Done with rebuilt packet, marking rebuilt...\n");

    ft->frag_flags |= FRAG_REBUILT;
}

/**
 * Plug a Fragment into the fraglist of a FragTracker
 *
 * @param ft FragTracker to put the new node into
 * @param prev ptr to preceding Fragment in fraglist
 * @param next ptr to following Fragment in fraglist
 * @param node ptr to node to put in list
 *
 * @return none
 */
static inline void add_node(FragTracker* ft, Fragment* prev, Fragment* node)
{
    if (prev)
    {
        node->next = prev->next;
        node->prev = prev;
        prev->next = node;
        if (node->next)
            node->next->prev = node;
        else
            ft->fraglist_tail = node;
    }
    else
    {
        node->next = ft->fraglist;
        if (node->next)
            node->next->prev = node;  // FIXIT-W Use of memory after it is freed
        else
            ft->fraglist_tail = node;
        ft->fraglist = node;
    }

    ft->fraglist_count++;
}

static inline void delete_node(FragTracker* ft, Fragment* node)
{
    trace_logf(stream_ip, "Deleting list node %p (p %p n %p)\n",
        (void*) node, (void*) node->prev, (void*) node->next);

    if (node->prev)
    {
        node->prev->next = node->next;
    }
    else
    {
        ft->fraglist = node->next;
    }

    if (node->next)
    {
        node->next->prev = node->prev;
    }
    else
    {
        ft->fraglist_tail = node->prev;
    }

    delete node;
    ft->fraglist_count--;
}

// Delete the contents of a FragTracker, in this instance that just means to
// dump the fraglist.

static void delete_tracker(FragTracker* ft)
{
    Fragment* idx = ft->fraglist;  /* pointer to the fraglist to delete */
    Fragment* dump_me = nullptr;      /* ptr to the Fragment element to drop */

    trace_logf(stream_ip,
        "delete_tracker %d nodes to dump\n", ft->fraglist_count);

    /*
     * delete all the nodes in a fraglist
     */
    while (idx)
    {
        dump_me = idx;
        idx = idx->next;
        delete dump_me;
    }
    ft->fraglist = nullptr;
    if (ft->ip_options_data)
    {
        snort_free(ft->ip_options_data);
        ft->ip_options_data = nullptr;
    }

    ip_stats.trackers_cleared++;
}

static void release_tracker(FragTracker* ft)
{
    delete_tracker(ft);
    ft->engine = nullptr;

    ip_stats.trackers_released++;
}

//-------------------------------------------------------------------------
// Defrag methods
//-------------------------------------------------------------------------

Defrag::Defrag(FragEngine& e) : engine(e), layers(DEFAULT_LAYERMAX) { }

bool Defrag::configure(SnortConfig* sc)
{
    // FIXIT-L kinda squiffy ... set for each instance (but to same value) ... move to tinit() ?
    layers = sc->get_num_layers();
    return true;
}

void Defrag::show(SnortConfig*)
{
    FragPrintEngineConfig(&engine);
}

void Defrag::cleanup(FragTracker* ft)
{
    if ( !ft->engine )
        return;

    release_tracker(ft);
}

void Defrag::process(Packet* p, FragTracker* ft)
{
    FragEngine* fe = &engine;
    int insert_return = 0;   /* return value from the insert function */

    // preconditions - what we registered for
    assert(p->has_ip() && !(p->ptrs.decode_flags & DECODE_ERR_CKSUM_IP));
    assert(p->is_fragment());

    const uint16_t frag_offset = p->ptrs.ip_api.off();

    /*
     * First case: if frag offset is 0 & UDP, let that packet go
     * through the rest of the system.  Ugly HACK to detect DNS
     * attack on 0 offset UDP.
     *
     * Second case: If frag offset is 0 & !more frags, this is a
     * full-frame "fragment", let the packet go through the rest
     * of the system.
     *
     * In other words:
     *   a = frag_offset != 0
     *   b = !UDP
     *   c = More Fragments
     *
     * if (a | (b & c))
     *    Disable Inspection since we'll look at the payload in
     *    a rebuilt packet later.  So don't process it further.
     */
    //  FIXIT-M since we no longer let UDP through, does this detection still work?
    if ((frag_offset != 0)) /* ||
        ((p->get_ip_proto_next() != IpProtocol::UDP) && (p->ptrs.decode_flags & DECODE_MF))) */
    {
        DetectionEngine::disable_content(p);
    }

    /*
     * pkt's not going to make it to the engine, bail
     */
    if (p->ptrs.ip_api.ttl() < fe->min_ttl)
    {
#ifdef DEBUG_MSGS
        if ( p->is_ip4() )
        {
            trace_logf(stream_ip,
                "[FRAG] Fragment discarded due to low TTL "
                "[0x%X->0x%X], TTL: %d  " "Offset: %d Length: %hu\n",
                ntohl(p->ptrs.ip_api.get_ip4h()->get_src()),
                ntohl(p->ptrs.ip_api.get_ip4h()->get_dst()),
                p->ptrs.ip_api.ttl(), frag_offset,
                p->dsize);
        }
#endif

        EventAnomMinTtl(fe);
        ip_stats.discards++;
        return;
    }

    ip_stats.total++;
    ip_stats.fragmented_bytes += p->pkth->caplen + 4; /* 4 for the CRC */

    Profile profile(fragPerfStats);

    if (!ft->engine )
    {
        new_tracker(p, ft);
        return;
    }
    else if (expired(p, ft, fe) )
    {
        /* Time'd out FragTrackers are just purged of their packets.
         * Reset the timestamp per this packet.
         * And reset the rest of the tracker as if this is the
         * first packet on the tracker, and continue. */

        /* This fixes an issue raised on bugtraq relating to
         * timeout frags not getting purged correctly when
         * the entire set of frags show up later. */

        ft->ttl = p->ptrs.ip_api.ttl(); /* store the first ttl we got */
    }

    // Update frag time when we get a frag associated with this tracker
    ft->frag_time.tv_sec = p->pkth->ts.tv_sec;
    ft->frag_time.tv_usec = p->pkth->ts.tv_usec;

    //don't forward fragments to engine if some previous fragment was dropped
    if ( ft->frag_flags & FRAG_DROP_FRAGMENTS )
    {
        DetectionEngine::disable_content(p);
        Active::daq_drop_packet(p);
        ip_stats.drops++;
    }

    /*
     * insert the fragment into the FragTracker
     */
    if ((insert_return = insert(p, ft, fe)) != FRAG_INSERT_OK)
    {
        /*
         * we can pad this switch out for a variety of entertaining behaviors
         * later if we're so inclined
         */
        switch (insert_return)
        {
        case FRAG_INSERT_FAILED:
            trace_logf(stream_ip, "WARNING: Insert into Fraglist failed, "
                "(offset: %hu).\n", frag_offset);
            return;

        case FRAG_INSERT_TTL:

#ifdef DEBUG_MSGS
            if ( p->is_ip4() )
            {
                trace_logf(stream_ip,
                    "[FRAG] Fragment discarded due to large TTL Delta "
                    "[0x%X->0x%X], TTL: %d  orig TTL: %d "
                    "Offset: %hu Length: %hu\n",
                    ntohl(p->ptrs.ip_api.get_ip4h()->get_src()),
                    ntohl(p->ptrs.ip_api.get_ip4h()->get_dst()),
                    p->ptrs.ip_api.ttl(), ft->ttl, frag_offset,
                    p->dsize);
            }
#endif
            ip_stats.discards++;
            return;

        case FRAG_INSERT_ATTACK:
        case FRAG_INSERT_ANOMALY:
            ip_stats.discards++;
            return;

        case FRAG_INSERT_TIMEOUT:
            trace_logf(stream_ip, "WARNING: Insert into Fraglist failed due to timeout, "
                "(offset: %hu).\n", frag_offset);
            return;

        case FRAG_INSERT_OVERLAP_LIMIT:
            trace_logf(stream_ip,
                "WARNING: Excessive IP fragment overlap, "
                "(More: %d, offset: %d, offsetSize: %hu).\n",
                (p->ptrs.decode_flags & DECODE_MF),
                (frag_offset << 3), p->dsize);
            ip_stats.discards++;
            return;

        default:
            break;
        }
    }

    /*
     * check to see if it's reassembly time
     */
    if (FragIsComplete(ft))
    {
        trace_log(stream_ip, "[*] Fragment is complete, rebuilding!\n");

        /*
         * if the frag completes but it's bad we're just going to drop it
         * instead of wasting time on putting it back together
         */
        if (!(ft->frag_flags & FRAG_BAD))
            FragRebuild(ft, p);

        if (Active::packet_was_dropped())
        {
            ft->frag_flags |= FRAG_DROP_FRAGMENTS;
            delete_tracker(ft);
        }
        else
        {
            release_tracker(ft);
            p->flow->session_state |= STREAM_STATE_CLOSED;
        }
    }
}

/**
 * This is where the rubber hits the road.  Insert the new fragment's data
 * into the current FragTracker's fraglist, doing anomaly detection and
 * handling overlaps in a engine-based manner.
 *
 * @param p Current packet to insert
 * @param ft FragTracker to hold the packet
 * @param engine engine of the current engine for engine-based defrag info
 *
 * @return status
 * @retval FRAG_INSERT_TIMEOUT FragTracker has timed out and been dropped
 * @retval FRAG_INSERT_ATTACK  Attack detected during insertion
 * @retval FRAG_INSERT_ANOMALY Anomaly detected during insertion
 * @retval FRAG_INSERT_TTL Delta of TTL values beyond configured value
 * @retval FRAG_INSERT_OK Fragment has been inserted successfully
 */
int Defrag::insert(Packet* p, FragTracker* ft, FragEngine* fe)
{
    uint16_t orig_offset;    /* offset specified in this fragment header */
    uint16_t frag_offset;    /* calculated offset for this fragment */
    uint16_t frag_end;       /* calculated end point for this fragment */
    int16_t trunc = 0;      /* we truncate off the tail */
    int32_t overlap = 0;    /* we overlap on either end of the frag */
    int16_t len = 0;        /* calculated size of the fragment */
    int16_t slide = 0;      /* slide up the front of the current frag */
    int done = 0;           /* flag for right-side overlap handling loop */
    int addthis = 1;           /* flag for right-side overlap handling loop */
    int i = 0;              /* counter */
    int firstLastOk;
    int ret = FRAG_INSERT_OK;
    unsigned char lastfrag = 0; /* Set to 1 when this is the 'last' frag */
    unsigned char alerted_overlap = 0; /* Set to 1 when alerted */
    Fragment* right = nullptr; /* frag ptr for right-side overlap loop */
    Fragment* newfrag = nullptr;  /* new frag container */
    Fragment* left = nullptr;     /* left-side overlap fragment ptr */
    Fragment* idx = nullptr;      /* indexing fragment pointer for loops */
    Fragment* dump_me = nullptr;  /* frag ptr for complete overlaps to dump */
    const uint8_t* fragStart;
    int16_t fragLength;
    const uint16_t net_frag_offset = p->ptrs.ip_api.off();

    Profile profile(fragInsertPerfStats);

    if (p->is_ip6() && (net_frag_offset == 0))
    {
        const ip::IP6Frag* const fragHdr = layer::get_inner_ip6_frag();
        if (ft->ip_proto != fragHdr->ip6f_nxt)
        {
            ft->ip_proto = fragHdr->ip6f_nxt;
        }
    }

    /*
     * Check to see if this fragment is the first or last one and
     * set the appropriate flags and values in the FragTracker
     */
    firstLastOk = FragCheckFirstLast(p, ft, net_frag_offset);

    /* Use the actual length here because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. Use dsize as the frag length since it is distance
     * between the last succesfully decoded layer (which is ip6_frag
     *  or ipv4) and the end of packet, */
    len = fragLength = p->dsize;
    fragStart = p->data;

    /*
     * setup local variables for tracking this frag
     */
    orig_offset = frag_offset = net_frag_offset;
    /* Reset the offset to handle the weird Solaris case */
    if (firstLastOk == FRAG_LAST_OFFSET_ADJUST)
        frag_offset = (uint16_t)ft->calculated_size;

    if (IP_MAXPACKET - frag_offset < fragLength)
    {
        trace_log(stream_ip, "[..] Oversize frag!\n");
        EventAnomBadsizeLg(fe);
        ft->frag_flags |= FRAG_BAD;
        return FRAG_INSERT_ANOMALY;
    }

    frag_end = frag_offset + fragLength;

    /*
     * might have last frag...
     */
    if (!(p->ptrs.decode_flags & DECODE_MF))
    {
        if ((frag_end > ft->calculated_size) &&
            (firstLastOk == FRAG_LAST_OFFSET_ADJUST))
        {
            ft->calculated_size = frag_end;
        }

        //    ft->frag_flags |= FRAG_GOT_LAST;
        //    ft->calculated_size = (p->frag_offset) + fragLength;
        lastfrag = 1;
    }
    else
    {
        uint16_t oldfrag_end;
        /*
         * all non-last frags are supposed to end on 8-byte boundaries
         */
        if (frag_end & 7)
        {
            /*
             * bonk/boink/jolt/etc attack...
             */
            trace_log(stream_ip,
                "[..] Short frag (Bonk, etc) attack!\n");

            EventAnomShortFrag(fe);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        oldfrag_end = frag_end;
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        len -= (oldfrag_end - frag_end);

        /*
         * if the end of this frag is greater than the max frag size we have a
         * problem
         */
        if (frag_end > ft->calculated_size)
        {
            if (ft->frag_flags & FRAG_GOT_LAST)
            {
                /* oversize frag attack */
                trace_log(stream_ip,
                    "[..] Oversize frag pkt!\n");

                EventAnomOversize(fe);

                return FRAG_INSERT_ANOMALY;
            }
            ft->calculated_size = frag_end;
        }
    }

    if (frag_end == frag_offset)
    {
        /*
         * zero size frag...
         */
        trace_log(stream_ip,
            "[..] Zero size frag!\n");

        EventAnomZeroFrag(fe);

        return FRAG_INSERT_ANOMALY;
    }


    /*
     * This may alert on bad options, but we still want to
     * insert the packet
     */
    if ( p->is_ip4() )
        FragHandleIPOptions(ft, p, frag_offset);

    ft->frag_pkts++;

    trace_logf(stream_ip,
        "Walking frag list (%d nodes), new frag %d@%d\n",
        ft->fraglist_count, fragLength, frag_offset);

    /*
     * Need to figure out where in the frag list this frag should go
     * and who its neighbors are
     */
    for (idx = ft->fraglist; idx; idx = idx->next)
    {
        i++;
        right = idx;

        trace_logf(stream_ip,
            "%d right o %d s %d ptr %p prv %p nxt %p\n",
            i, right->offset, right->size, (void*) right,
            (void*) right->prev, (void*) right->next);

        if (right->offset >= frag_offset)
        {
            break;
        }

        left = right;
    }

    /*
     * null things out if we walk to the end of the list
     */
    if (idx == nullptr)
        right = nullptr;

    /*
     * handle forward (left-side) overlaps...
     */
    if (left)
    {
        trace_logf(stream_ip,
            "Dealing with previous (left) frag %d@%d\n",
            left->size, left->offset);

        /*
         * generate the overlap of the current packet fragment
         * over this left-side fragment
         */
        /* NOTE: If frag_offset is really large, overlap can be
         * negative because its stored as a 32bit int.
         */
        overlap = left->offset + left->size - frag_offset;

        if (overlap > 0)
        {
            ip_stats.overlaps++;
            ft->overlap_count++;

            if (frag_end < ft->calculated_size ||
                ((ft->frag_flags & FRAG_GOT_LAST) &&
                frag_end != ft->calculated_size))
            {
                if (!(p->ptrs.decode_flags & DECODE_MF))
                {
                    /*
                     * teardrop attack...
                     */
                    trace_log(stream_ip,
                        "[..] Teardrop attack!\n");

                    EventAttackTeardrop(fe);

                    ft->frag_flags |= FRAG_BAD;

                    return FRAG_INSERT_ATTACK;
                }
            }

            /*
             * Ok, we've got an overlap so we need to handle it.
             *
             * The engine-based modes here match the data generated by
             * Paxson's Active Mapping paper as do the policy types.
             */
            switch (ft->frag_policy)
            {
            /*
             * new frag gets moved around
             */
            case FRAG_POLICY_LINUX:
            case FRAG_POLICY_FIRST:
            case FRAG_POLICY_WINDOWS:
            case FRAG_POLICY_SOLARIS:
            case FRAG_POLICY_BSD:
                frag_offset += (int16_t)overlap;
                slide = (int16_t)overlap;

                trace_logf(stream_ip,
                    "left overlap, new frag moves: %d bytes, "
                    "slide: %d\n", overlap, slide);

                if (frag_end <= frag_offset)
                {
                    /*
                     * zero size frag
                     */
                    trace_log(stream_ip,
                        "zero size frag\n");

                    EventAnomZeroFrag(fe);

                    return FRAG_INSERT_ANOMALY;
                }

                trace_logf(stream_ip, "left overlap, "
                    "truncating new pkt (slide: %d)\n", slide);

                break;

            /*
             * new frag stays where it is, overlapee (existing frag)
             * gets whacked
             */
            case FRAG_POLICY_BSD_RIGHT:
                if (left->offset + left->size >= frag_offset + len)
                {
                    /* BSD-right (HP Printers) favor new fragments with
                     * lower/equal offset, EXCEPT when the existing
                     * fragment ends with at a higher/equal offset.
                     */
                    frag_offset += (int16_t)overlap;
                    slide = (int16_t)overlap;
                    goto left_overlap_last;
                }
            /* fall through */
            case FRAG_POLICY_LAST:
                if ((left->offset < frag_offset) && (left->offset + left->size > frag_offset +
                    len))
                {
                    /* The new frag is overlapped on both sides by an
                     * existing frag -- existing frag needs to be split
                     * and the new frag inserted in the middle.
                     *
                     * Need to duplicate left.  Adjust that guys
                     * offset by + (frag_offset + len) and
                     * size by - (frag_offset + len - left->offset).
                     */
                    ret = dup_frag_node(ft, left, &right);
                    if (ret != FRAG_INSERT_OK)
                    {
                        /* Some warning here,
                         * no, its done in add_frag_node */
                        return ret;
                    }
                    left->size -= (int16_t)overlap;
                    ft->frag_bytes -= (int16_t)overlap;

                    right->offset = frag_offset + len;
                    right->size -= (frag_offset + len - left->offset);
                    right->data += (frag_offset + len - left->offset);
                    ft->frag_bytes -= (frag_offset + len - left->offset);
                }
                else
                {
                    left->size -= (int16_t)overlap;
                    ft->frag_bytes -= (int16_t)overlap;
                }

left_overlap_last:
                trace_logf(stream_ip, "[!!] left overlap, "
                    "truncating old pkt (offset: %d overlap: %d)\n",
                    left->offset, overlap);

                if (left->size <= 0)
                {
                    dump_me = left;

                    trace_logf(stream_ip, "retrans, "
                        "dumping old frag (offset: %d overlap: %d)\n",
                        dump_me->offset, overlap);

                    left = left->prev;

                    delete_node(ft, dump_me);
                }

                break;
            }

            /*
             * frag can't end before it begins...
             */
            if (frag_end < frag_offset)
            {
                trace_log(stream_ip,
                    "frag_end < frag_offset!");

                EventAnomBadsizeSm(fe);

                return FRAG_INSERT_ANOMALY;
            }
        }
        else
        {
            trace_log(stream_ip, "No left overlap!\n");
        }
    }

    if ((uint16_t)fragLength > SFDAQ::get_snap_len())
    {
        trace_logf(stream_ip,
            "Overly large fragment %d 0x%x 0x%x %d\n",
            fragLength, p->ptrs.ip_api.dgram_len(), p->ptrs.ip_api.off(),
            net_frag_offset);
        return FRAG_INSERT_FAILED;
    }

    /*
     * handle tail (right-side) overlaps
     *
     * We have to walk thru all the right side frags until the offset of the
     * existing frag is greater than the end of the new frag
     */
    while (right && (right->offset < frag_end) && !done)
    {
        trace_logf(stream_ip,
            "Next (right)fragment %d@%d\n",
            right->size, right->offset);

        trunc = 0;
        overlap = frag_end - right->offset;

        if (overlap)
        {
            if (frag_end < ft->calculated_size ||
                ((ft->frag_flags & FRAG_GOT_LAST) &&
                frag_end != ft->calculated_size))
            {
                if (!(p->ptrs.decode_flags & DECODE_MF))
                {
                    /*
                     * teardrop attack...
                     */
                    trace_log(stream_ip,
                        "[..] Teardrop attack!\n");

                    EventAttackTeardrop(fe);

                    ft->frag_flags |= FRAG_BAD;

                    return FRAG_INSERT_ATTACK;
                }
            }
        }

        /*
         * partial right-side overlap, this will be the last frag to check
         */
        if (overlap < right->size)
        {
            ip_stats.overlaps++;
            ft->overlap_count++;

            trace_logf(stream_ip,
                "Right-side overlap %d bytes\n", overlap);

            /*
             * once again, engine-based policy processing
             */
            switch (ft->frag_policy)
            {
            /*
             * existing fragment gets truncated
             */
            case FRAG_POLICY_LAST:
            case FRAG_POLICY_LINUX:
            case FRAG_POLICY_BSD:
                if ((ft->frag_policy == FRAG_POLICY_BSD) &&
                    (right->offset == frag_offset))
                {
                    slide = (int16_t)(right->offset + right->size - frag_offset);
                    frag_offset += (int16_t)slide;
                }
                else
                {
                    right->offset += (int16_t)overlap;
                    right->data += (int16_t)overlap;
                    right->size -= (int16_t)overlap;
                    ft->frag_bytes -= (int16_t)overlap;
                }
                trace_logf(stream_ip, "[!!] right overlap, "
                    "truncating old frag (offset: %d, "
                    "overlap: %d)\n", right->offset, overlap);
                trace_log(stream_ip,
                    "Exiting right overlap loop...\n");
                if (right->size <= 0)
                {
                    dump_me = right;

                    trace_logf(stream_ip, "retrans, "
                        "dumping old frag (offset: %d overlap: %d)\n",
                        dump_me->offset, overlap);

                    right = right->next;

                    delete_node(ft, dump_me);
                }
                break;

            /*
             * new frag gets truncated
             */
            case FRAG_POLICY_FIRST:
            case FRAG_POLICY_WINDOWS:
            case FRAG_POLICY_SOLARIS:
            case FRAG_POLICY_BSD_RIGHT:
                trunc = (int16_t)overlap;
                trace_logf(stream_ip, "[!!] right overlap, "
                    "truncating new frag (offset: %d "
                    "overlap: %d)\n",
                    right->offset, overlap);
                trace_log(stream_ip,
                    "Exiting right overlap loop...\n");
                break;
            }

            /*
             * all done, bail
             */
            done = 1;
        }
        else
        {
            /*
             * we've got a full overlap
             */
            if ( !alerted_overlap )
            {
                /*
                 * retrans/full overlap
                 */
                EventAnomOverlap(fe);
                alerted_overlap = 1;
                ip_stats.overlaps++;
                ft->overlap_count++;
            }

            /*
             * handle the overlap in a engine-based manner
             */
            switch (ft->frag_policy)
            {
            /*
             * overlap is treated differently if there is more
             * data beyond the overlapped packet.
             */
            case FRAG_POLICY_WINDOWS:
            case FRAG_POLICY_SOLARIS:
            case FRAG_POLICY_BSD:
                /*
                 * Old packet is overlapped on both sides...
                 * Drop the old packet.  This follows a
                 * POLICY_LAST model.
                 */
                if ((frag_end > right->offset + right->size) &&
                    (frag_offset < right->offset))
                {
                    dump_me = right;
                    ft->frag_bytes -= right->size;

                    trace_logf(stream_ip, "retrans, "
                        "dumping old frag (offset: %d overlap: %d)\n",
                        dump_me->offset, overlap);

                    right = right->next;

                    delete_node(ft, dump_me);
                    break;
                }
                else
                {
                    if ((ft->frag_policy == FRAG_POLICY_SOLARIS) ||
                        (ft->frag_policy == FRAG_POLICY_BSD))
                    {
                        /* SOLARIS & BSD only */
                        if ((frag_end == right->offset + right->size) &&
                            (frag_offset < right->offset))
                        {
                            /* If the frag overlaps an entire frag to the
                             * right side of that frag, the old frag if
                             * dumped -- this is a "policy last".
                             */
                            goto right_overlap_last;
                        }
                    }
                }
            /* Otherwise, treat it as a POLICY_FIRST,
             * and trim accordingly. */

            /* fallthrough */

            /*
             * overlap is rejected
             */
            case FRAG_POLICY_FIRST:
                /* fix for bug 17823 */
                if (right->offset == frag_offset)
                {
                    slide = (int16_t)(right->offset + right->size - frag_offset);
                    frag_offset += (int16_t)slide;
                    left = right;
                    right = right->next;
                }
                else
                {
                    trunc = (int16_t)overlap;
                }

                trace_logf(stream_ip, "right overlap, "
                    "rejecting new overlap data (overlap: %d, "
                    "trunc: %d)\n", overlap, trunc);

                if (frag_end - trunc <= frag_offset)
                {
                    /*
                     * zero size frag
                     */
                    trace_logf(stream_ip,
                        "zero size frag (len: %d  overlap: %d)\n",
                        fragLength, overlap);

                    ip_stats.discards++;

                    return FRAG_INSERT_ANOMALY;
                }

                {
                    uint16_t curr_end;
                    /* Full overlapping an already received packet
                     * and there are more packets beyond that fully
                     * overlapped one.
                     * Arrgh.  Need to insert this guy in chunks.
                     */
                    checkTinyFragments(fe, p, len-slide-trunc);

                    ret = add_frag_node(ft, fe, fragStart, fragLength, 0, len,
                        slide, trunc, frag_offset, left, &newfrag);
                    if (ret != FRAG_INSERT_OK)
                    {
                        /* Some warning here,
                         * no, its done in add_frag_node */
                        return ret;
                    }

                    curr_end = newfrag->offset + newfrag->size;

                    /* Find the next gap that this one might fill in */
                    while (right &&
                        (curr_end == right->offset) &&
                        (right->offset < frag_end))
                    {
                        curr_end = right->offset + right->size;
                        left = right;
                        right = right->next;
                    }

                    if (right && (right->offset < frag_end))
                    {
                        /* Adjust offset to end of 'left' */
                        if (left)
                            frag_offset = left->offset + left->size;
                        else
                            frag_offset = orig_offset;

                        /* Overlapping to the left by a good deal now */
                        slide = frag_offset - orig_offset;
                        /*
                         * Reset trunc, in case the next one kicks us
                         * out of the loop.  This packet will become the
                         * right-most entry so far.  Don't truncate any
                         * further.
                         */
                        trunc = 0;
                        if (right)
                            continue;
                    }

                    if (curr_end < frag_end)
                    {
                        /* Insert this guy in his proper spot,
                         * adjust offset to the right-most endpoint
                         * we saw.
                         */
                        slide = left->offset + left->size - frag_offset;
                        frag_offset = curr_end;
                        trunc = 0;
                    }
                    else
                    {
                        addthis = 0;
                    }
                }
                break;

                /*
                 * retrans accepted, dump old frag
                 */
right_overlap_last:
            case FRAG_POLICY_BSD_RIGHT:
            case FRAG_POLICY_LAST:
            case FRAG_POLICY_LINUX:
                dump_me = right;
                ft->frag_bytes -= right->size;

                trace_logf(stream_ip, "retrans, "
                    "dumping old frag (offset: %d overlap: %d)\n",
                    dump_me->offset, overlap);

                right = right->next;

                delete_node(ft, dump_me);

                break;
            }
        }
    }

    // detect tiny fragments but continue processing
    checkTinyFragments(fe, p, len-slide-trunc);

    if ((fe->max_overlaps) &&
        (ft->overlap_count >= fe->max_overlaps))
    {
        // overlap limit exceeded. Raise event on all subsequent fragments
        trace_log(stream_ip, "Reached overlap limit.\n");

        EventExcessiveOverlap(fe);

        return FRAG_INSERT_OVERLAP_LIMIT;
    }

    if (addthis)
    {
        ret = add_frag_node(ft, fe, fragStart, fragLength, lastfrag, len,
            slide, trunc, frag_offset, left, &newfrag);
    }
    else
    {
        trace_log(stream_ip,
            "Fully truncated right overlap\n");
    }

    trace_log(stream_ip,
        "insert(): returning normally\n");

    return ret;
}

/**
 * @param p Current packet to fill in FragTracker fields
 *
 * @return status
 * @retval 0 on an error
 * @retval 1 on success
 */
int Defrag::new_tracker(Packet* p, FragTracker* ft)
{
    Fragment* f = nullptr;
    //int ret = 0;
    const uint8_t* fragStart;
    uint16_t fragLength;
    uint16_t frag_end;
    uint16_t frag_off;

    /* Use the actual length here because packet may have been
     * truncated.  Don't want to try to copy more than we actually
     * captured. Use dsize as the frag length since it is distance
     * between the last succesfully decoded layer (which is ip6_frag
     *  or ipv4) and the end of packet, */
    fragLength = p->dsize;
    fragStart = p->data;

    /* Just to double check */
    if (!fragLength or fragLength > SFDAQ::get_snap_len())
    {
        trace_logf(stream_ip,
            "Bad fragment length:%d(0x%x) off:0x%x(%d)\n",
            fragLength, p->ptrs.ip_api.dgram_len(), p->ptrs.ip_api.off(),
            p->ptrs.ip_api.off());

        /* Ah, crap.  Return that tracker. */
        return 0;
    }

    memset(ft, 0, sizeof(*ft));

    if ( p->is_ip4() )
    {
        const ip::IP4Hdr* const ip4h = p->ptrs.ip_api.get_ip4h();
        ft->ip_proto = ip4h->proto();
        frag_off = ip4h->off();
    }
    else /* IPv6 */
    {
        const Layer& lyr = p->layers[p->num_layers-1];
        const ip::IP6Frag* const fragHdr = reinterpret_cast<const ip::IP6Frag*>(lyr.start);
        frag_off = fragHdr->off();

        if (frag_off == 0)
            ft->ip_proto = fragHdr->ip6f_nxt;
    }

    ft->ttl = p->ptrs.ip_api.ttl(); /* store the first ttl we got */
    ft->calculated_size = 0;
    ft->alerted = 0;
    ft->frag_flags = 0;
    ft->frag_bytes = 0;
    ft->frag_pkts = 0;
    ft->frag_time.tv_sec = p->pkth->ts.tv_sec;
    ft->frag_time.tv_usec = p->pkth->ts.tv_usec;
    ft->alert_count = 0;
    ft->ip_options_len = 0;
    ft->ip_options_data = nullptr;
    ft->copied_ip_options_len = 0;
    ft->ordinal = 0;
    ft->frag_policy = p->flow->ssn_policy ? p->flow->ssn_policy : engine.frag_policy;
    ft->engine = &engine;

    /* initialize the fragment list */
    ft->fraglist = nullptr;

    f = new Fragment(fragLength, fragStart, ft->ordinal++);

    f->size = fragLength;
    f->offset = frag_off;
    f->data = f->fptr;     /* ptr to adjusted start position */

    frag_end = f->offset + fragLength;
    if (!(p->ptrs.decode_flags & DECODE_MF))
    {
        f->last = 1;
    }
    else
    {
        /*
         * all non-last frags are supposed to end on 8-byte boundaries
         */
        if (frag_end & 7)
        {
            /*
             * bonk/boink/jolt/etc attack...
             */
            trace_log(stream_ip,
                "[..] Short frag (Bonk, etc) attack!\n");

            EventAnomShortFrag(&engine);

            /* don't return, might still be interesting... */
        }

        /* can't have non-full fragments... */
        frag_end &= ~7;

        /* Adjust len to take into account the jolting/non-full fragment. */
        f->size = frag_end - f->offset;
    }

    /* insert the fragment into the frag list */
    ft->fraglist = f;
    ft->fraglist_tail = f;
    ft->fraglist_count = 1;  /* XXX: Are these duplicates? */
    ft->frag_pkts = 1;

    /*
     * mark the FragTracker if this is the first/last frag
     */
    FragCheckFirstLast(p, ft, frag_off);

    ft->frag_bytes += fragLength;

    if ( p->is_ip4() )
        FragHandleIPOptions(ft, p, frag_off);

    return 1;
}

/**
 * Handle the creation of the new frag node and list insertion.
 * Separating this from actually calculating the values.
 *
 * @param ft FragTracker to hold the packet
 * @param fragStart Pointer to start of the packet data
 * @param fragLength Length of packet data
 * @param len Length of this fragment
 * @param slide Adjustment to make to left side of data (for left overlaps)
 * @param trunc Adjustment to make to right side of data (for right overlaps)
 * @param frag_offset Offset for this fragment
 * @param left FragNode prior to this one
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
int Defrag::add_frag_node(
    FragTracker* ft,
    FragEngine*,
    const uint8_t* fragStart,
    int16_t fragLength,
    char lastfrag,
    int16_t len,
    uint16_t slide,
    uint16_t trunc,
    uint16_t frag_offset,
    Fragment* left,
    Fragment** retFrag)
{
    Fragment* newfrag = nullptr;  /* new frag container */
    int16_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /*
         * zero size frag
         */
        trace_logf(stream_ip,
            "zero size frag after left & right trimming "
            "(len: %d  slide: %d  trunc: %d)\n",
            len, slide, trunc);

        ip_stats.discards++;

#ifdef DEBUG_MSGS
        newfrag = ft->fraglist;
        while (newfrag)
        {
            trace_logf(stream_ip,
                "Size: %d, offset: %d, len %d, "
                "Prev: 0x%p, Next: 0x%p, This: 0x%p, Ord: %d, %s\n",
                newfrag->size, newfrag->offset,
                newfrag->flen, (void*) newfrag->prev,
                (void*) newfrag->next, (void*) newfrag, newfrag->ord,
                newfrag->last ? "Last" : "");
            newfrag = newfrag->next;
        }
#endif

        return FRAG_INSERT_ANOMALY;
    }

    newfrag = new Fragment(fragLength, fragStart, ft->ordinal++);

    /*
     * twiddle the frag values for overlaps
     */
    newfrag->data = newfrag->fptr + slide;
    newfrag->size = newSize;
    newfrag->offset = frag_offset;
    newfrag->last = lastfrag;

    trace_logf(stream_ip,
        "[+] Adding new frag, offset %d, size %d\n"
        "   nf->data = nf->fptr(%p) + slide (%d)\n"
        "   nf->size = len(%d) - slide(%d) - trunc(%d)\n",
        newfrag->offset, newfrag->size, newfrag->fptr,
        slide, fragLength, slide, trunc);

    /*
     * insert the new frag into the list
     */
    add_node(ft, left, newfrag);

    trace_logf(stream_ip,
        "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n",
        newfrag->size, newfrag->offset, (void*) newfrag, newfrag->data,
        (void*) newfrag->prev, (void*) newfrag->next);

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    trace_logf(stream_ip,
        "[#] accumulated bytes on FragTracker %u, count"
        " %d\n", ft->frag_bytes, ft->fraglist_count);

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * Duplicate a frag node and insert it into the list.
 *
 * @param ft FragTracker to hold the packet
 * @param left FragNode prior to this one (to be dup'd)
 * @param retFrag this one after its inserted (returned)
 *
 * @return status
 * @retval FRAG_INSERT_FAILED Memory problem, insertion failed
 * @retval FRAG_INSERT_OK All okay
 */
int Defrag::dup_frag_node( FragTracker* ft, Fragment* left, Fragment** retFrag)
{
    Fragment* newfrag = new Fragment(left, ft->ordinal++);

    add_node(ft, left, newfrag);

    trace_logf(stream_ip,
        "[*] Inserted new frag %d@%d ptr %p data %p prv %p nxt %p\n",
        newfrag->size, newfrag->offset, (void*) newfrag, newfrag->data,
        (void*) newfrag->prev, (void*) newfrag->next);

    /*
     * record the current size of the data in the fraglist
     */
    ft->frag_bytes += newfrag->size;

    trace_logf(stream_ip,
        "[#] accumulated bytes on FragTracker %u, count"
        " %d\n", ft->frag_bytes, ft->fraglist_count);

    *retFrag = newfrag;
    return FRAG_INSERT_OK;
}

/**
 * Time-related expiration of fragments from the system.  Checks the current
 * FragTracker for timeout, then walks up the LRU list looking to see if
 * anyone should have timed out.
 *
 * @param p Current packet (contains pointer to the current timestamp)
 * @param ft FragTracker to check for a timeout
 * @param engine instance of the defrag engine, contains the timeout value
 *
 * @return status
 * @retval FRAG_TRACKER_TIMEOUT The current FragTracker has timed out
 * @retval FRAG_OK The current FragTracker has not timed out
 */
inline int Defrag::expired(Packet* p, FragTracker* ft, FragEngine* fe)
{
    /*
     * Check the FragTracker that was passed in first
     */
    if ( frag_timed_out(&p->pkth->ts, &(ft)->frag_time, fe) )
    {
        // Oops, we've timed out, whack the FragTracker
        /*
         * Don't remove the tracker.
         * Remove all of the packets that are stored therein.
         *
         * If the existing tracker times out because of a delay
         * relative to the timeout
         */
        delete_tracker(ft);

        ip_stats.frag_timeouts++;

        return true;
    }

    return false;
}

