//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
/*    Dan Roelker <droelker@sourcefire.com>
**    Marc Norton <mnorton@sourcefire.com>
** NOTES
**   5.7.02: Added interface for new detection engine. (Norton/Roelker)
**
*/

#include "detect.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define FASTPKT

#include <string.h>
#include <stdlib.h>

#include "tag.h"
#include "pcrm.h"
#include "fp_create.h"
#include "fp_detect.h"
#include "signature.h"
#include "detection_util.h"
#include "detection_defines.h"

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "main/analyzer.h"
#include "utils/util.h"
#include "ports/port_object.h"
#include "filters/sfthreshold.h"
#include "events/event_wrapper.h"
#include "events/event_queue.h"
#include "log/obfuscation.h"
#include "time/profiler.h"
#include "time/ppm.h"
#include "stream/stream_api.h"
#include "packet_io/active.h"
#include "managers/inspector_manager.h"
#include "managers/event_manager.h"
#include "protocols/ip.h"
#include "sfip/sf_ipvar.h"

#define CHECK_SRC_IP         0x01
#define CHECK_DST_IP         0x02
#define INVERSE              0x04
#define CHECK_SRC_PORT       0x08
#define CHECK_DST_PORT       0x10

#ifdef PERF_PROFILING
THREAD_LOCAL ProfileStats detectPerfStats;
THREAD_LOCAL ProfileStats eventqPerfStats;
#endif

THREAD_LOCAL int do_detect;
THREAD_LOCAL int do_detect_content;

static THREAD_LOCAL char check_tags_flag;

static int CheckTagging(Packet*);

void snort_ignore(Packet*) { }

void snort_inspect(Packet* p)
{
    PROFILE_VARS;

#ifdef PPM_MGR
    uint64_t pktcnt=0;

    /* Begin Packet Performance Monitoring  */
    if ( PPM_PKTS_ENABLED() )
    {
        pktcnt = PPM_INC_PKT_CNT();
        PPM_GET_TIME();
        PPM_INIT_PKT_TIMER();

#ifdef DEBUG_MSGS
        if ( Debug::enabled(DEBUG_PPM) )
        {
            /* for debugging, info gathering, so don't worry about
            *  (unsigned) casting of pktcnt, were not likely to debug
            *  4G packets
            */
            LogMessage("PPM: Process-BeginPkt[%u] caplen=%u\n",
                (unsigned)pktcnt,p->pkth->caplen);
        }
#endif
    }
#endif

    bool inspected = false;

    // If the packet has errors, we won't analyze it.
    if ( p->ptrs.decode_flags & DECODE_ERR_FLAGS )
    {
        DebugFormat(DEBUG_DETECT,
            "Packet errors = 0x%x, ignoring traffic!\n",
            (p->ptrs.decode_flags & DECODE_ERR_FLAGS));

        if ( SnortConfig::inline_mode() and
            SnortConfig::checksum_drop(p->ptrs.decode_flags & DECODE_ERR_CKSUM_ALL) )
        {
            DebugMessage(DEBUG_DECODE, "Dropping bad packet\n");
            Active::drop_packet(p);
        }
    }
    else
    {
        /* Not a completely ideal place for this since any entries added on
         * the packet callback trail will get obliterated - right now there
         * isn't anything adding entries there.  Really need it here for
         * stream clean exit, since all of the flushed, reassembled
         * packets are going to be injected directly into this function and
         * there may be enough that the obfuscation entry table will
         * overflow if we don't reset it.  Putting it here does have the
         * advantage of fewer entries per logging cycle */
        obApi->resetObfuscationEntries();

        do_detect = do_detect_content = 1;

        /*
        **  Reset the appropriate application-layer protocol fields
        */
        p->alt_dsize = 0;

        InspectorManager::execute(p);
        inspected = true;

        if ( do_detect )
            snort_detect(p);
    }

    check_tags_flag = 1;

    MODULE_PROFILE_START(eventqPerfStats);
    SnortEventqLog(p);
    SnortEventqReset();
    MODULE_PROFILE_END(eventqPerfStats);

    /* Check for normally closed session */
    stream.check_session_closed(p);

    /*
    ** By checking tagging here, we make sure that we log the
    ** tagged packet whether it generates an alert or not.
    */
    if ( p->has_ip() )
        CheckTagging(p);

    if ( inspected )
        InspectorManager::clear(p);

#ifdef PPM_MGR
    if ( PPM_PKTS_ENABLED() )
    {
        PPM_GET_TIME();
        PPM_TOTAL_PKT_TIME();
        PPM_ACCUM_PKT_TIME();

#ifdef DEBUG_MSGS
        if ( Debug::enabled(DEBUG_PPM) )
        {
            // FIXIT-L logs should be debugs
            LogMessage("PPM: Pkt[%u] Used= ",(unsigned)pktcnt);
            PPM_PRINT_PKT_TIME("%g usecs\n");
            LogMessage("PPM: Process-EndPkt[%u]\n\n",(unsigned)pktcnt);
        }
#endif
        PPM_PKT_LOG(p);
    }
    if ( PPM_RULES_ENABLED() )
    {
        PPM_RULE_LOG(pktcnt, p);
    }
    if ( PPM_PKTS_ENABLED() )
    {
        PPM_END_PKT_TIMER();
    }
#endif
}

void snort_log(Packet* p)
{
    pc.log_pkts++;
    EventManager::call_loggers(NULL, p, NULL, NULL);
}

void CallLogFuncs(Packet* p, ListHead* head, Event* event, const char* msg)
{
    event->event_id = event_id | SnortConfig::get_event_log_id();

    check_tags_flag = 0;
    pc.log_pkts++;

    OutputSet* idx = head ? head->LogList : NULL;
    EventManager::call_loggers(idx, p, msg, event);
}

void CallLogFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)
{
    Event event;

    event.sig_info = &otn->sigInfo;
    event.ref_time.tv_sec = p->pkth->ts.tv_sec;
    event.ref_time.tv_usec = p->pkth->ts.tv_usec;
    event.event_id = event_id | SnortConfig::get_event_log_id();
    event.event_reference = event.event_id;

    check_tags_flag = 0;
    pc.log_pkts++;

    OutputSet* idx = head ? head->LogList : NULL;
    EventManager::call_loggers(idx, p, otn->sigInfo.message, &event);
}

void CallAlertFuncs(Packet* p, const OptTreeNode* otn, ListHead* head)
{
    Event event;

    event.sig_info = &otn->sigInfo;
    event.ref_time.tv_sec = p->pkth->ts.tv_sec;
    event.ref_time.tv_usec = p->pkth->ts.tv_usec;
    event.event_id = event_id | SnortConfig::get_event_log_id();
    event.event_reference = event.event_id;

    pc.total_alert_pkts++;

#if 0
    // FIXIT-M this should be a generic feature of otn
    if ( otn->sigInfo.generator != GENERATOR_SPP_REPUTATION )
    {
        /* Don't include IP Reputation events in count */
        pc.alert_pkts++;
    }
#endif

    OutputSet* idx = head ? head->AlertList : NULL;
    EventManager::call_alerters(idx, p, otn->sigInfo.message, &event);
}

/*
**  NAME
**    CheckTagging::
*/
/**
**  This is where we check to see if we tag the packet.  We only do
**  this if we've alerted on a non-pass rule and the packet is not
**  rebuilt.
**
**  We don't log rebuilt packets because the output plugins log the
**  individual packets of a rebuilt stream, so we don't want to dup
**  tagged packets for rebuilt streams.
**
**  @return integer
*/
int CheckTagging(Packet* p)
{
    Event event;

    if (check_tags_flag == 1 && !(p->packet_flags & PKT_REBUILT_STREAM))
    {
        void* listhead = NULL;
        DebugMessage(DEBUG_FLOW, "calling CheckTagList\n");

        if (CheckTagList(p, &event, &listhead))
        {
            DebugMessage(DEBUG_FLOW, "Matching tag node found, "
                "calling log functions\n");

            /* if we find a match, we want to send the packet to the
             * logging mechanism
             */
            CallLogFuncs(p, (ListHead*)listhead, &event, "Tagged Packet");
        }
    }

    return 0;
}

/****************************************************************************
 *
 * Function: snort_detect(Packet *)
 *
 * Purpose: Apply the rules lists to the current packet
 *
 * Arguments: p => ptr to the decoded packet struct
 *
 * Returns: 1 == detection event
 *          0 == no detection
 *
 ***************************************************************************/
bool snort_detect(Packet* p)
{
    if ((p == NULL) || !p->ptrs.ip_api.is_valid())
    {
        return false;
    }

    if (p->packet_flags & PKT_PASS_RULE)
    {
        /* If we've already seen a pass rule on this,
         * no need to continue do inspection.
         */
        return false;
    }

    // FIXIT-M:  Curently, if a rule is found on any IP layer, we
    //          perform the detect routine on the entire packet.
    //          Instead, we should only perform detect on that
    //          layer!!
    switch ( p->type() )
    {
    case PktType::IP:
    case PktType::TCP:
    case PktType::UDP:
    case PktType::ICMP:
    case PktType::PDU:
    case PktType::FILE:
    {
        PROFILE_VARS;

#       ifdef PPM_MGR
        /*
         * Packet Performance Monitoring
         * (see if preprocessing took too long)
         */
        if ( PPM_PKTS_ENABLED() )
        {
            PPM_GET_TIME();
            PPM_PACKET_TEST();

            if ( PPM_PACKET_ABORT_FLAG() )
                return false;
        }
#       endif /* PPM_MGR */

        /*
        **  This is where we short circuit so
        **  that we can do IP checks.
        */
        MODULE_PROFILE_START(detectPerfStats);
        int detected = fpEvalPacket(p);
        MODULE_PROFILE_END(detectPerfStats);

        return detected;
    }

    default:
        return false;
    }
}

static int CheckAddrPort(
    sfip_var_t* rule_addr,
    PortObject* po,
    Packet* p,
    uint32_t flags, int mode)
{
    const sfip_t* pkt_addr;          /* packet IP address */
    u_short pkt_port;                /* packet port */
    int global_except_addr_flag = 0; /* global exception flag is set */
    int any_port_flag = 0;           /* any port flag set */
    int except_port_flag = 0;        /* port exception flag set */
    int ip_match = 0;                /* flag to indicate addr match made */

    DebugMessage(DEBUG_DETECT, "CheckAddrPort: ");
    /* set up the packet particulars */
    if (mode & CHECK_SRC_IP)
    {
        pkt_addr = p->ptrs.ip_api.get_src();
        pkt_port = p->ptrs.sp;

        DebugMessage(DEBUG_DETECT,"SRC ");

        if (mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
    }
    else
    {
        pkt_addr = p->ptrs.ip_api.get_dst();
        pkt_port = p->ptrs.dp;

        DebugMessage(DEBUG_DETECT, "DST ");

        if (mode & INVERSE)
        {
            global_except_addr_flag = flags & EXCEPT_SRC_IP;
            any_port_flag = flags & ANY_SRC_PORT;
            except_port_flag = flags & EXCEPT_SRC_PORT;
        }
        else
        {
            global_except_addr_flag = flags & EXCEPT_DST_IP;
            any_port_flag = flags & ANY_DST_PORT;
            except_port_flag = flags & EXCEPT_DST_PORT;
        }
    }

    DebugFormat(DEBUG_DETECT, "addr %lx, port %d ", pkt_addr, pkt_port);

    if (!rule_addr)
        goto bail;

    if (!(global_except_addr_flag)) /*modeled after Check{Src,Dst}IP function*/
    {
        if (sfvar_ip_in(rule_addr, pkt_addr))
            ip_match = 1;
    }
    else
    {
        DebugMessage(DEBUG_DETECT, ", global exception flag set");
        /* global exception flag is up, we can't match on *any*
         * of the source addresses
         */

        if (sfvar_ip_in(rule_addr, pkt_addr))
            return 0;

        ip_match=1;
    }

bail:
    if (!ip_match)
    {
        DebugMessage(DEBUG_DETECT, ", no address match,  "
            "packet rejected\n");
        return 0;
    }

    DebugMessage(DEBUG_DETECT, ", addresses accepted");

    /* if the any port flag is up, we're all done (success) */
    if (any_port_flag)
    {
        DebugMessage(DEBUG_DETECT, ", any port match, "
            "packet accepted\n");
        return 1;
    }

    if (!(mode & (CHECK_SRC_PORT | CHECK_DST_PORT)))
    {
        return 1;
    }

    /* check the packet port against the rule port */
    if ( !PortObjectHasPort(po,pkt_port) )
    {
        /* if the exception flag isn't up, fail */
        if (!except_port_flag)
        {
            DebugMessage(DEBUG_DETECT, ", port mismatch,  "
                "packet rejected\n");
            return 0;
        }
        DebugMessage(DEBUG_DETECT, ", port mismatch exception");
    }
    else
    {
        /* if the exception flag is up, fail */
        if (except_port_flag)
        {
            DebugMessage(DEBUG_DETECT,
                ", port match exception,  packet rejected\n");
            return 0;
        }
        DebugMessage(DEBUG_DETECT, ", ports match");
    }

    /* ports and address match */
    DebugMessage(DEBUG_DETECT, ", packet accepted!\n");
    return 1;
}

#define CHECK_ADDR_SRC_ARGS(x) (x)->src_portobject
#define CHECK_ADDR_DST_ARGS(x) (x)->dst_portobject

int CheckBidirectional(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList*, int check_ports)
{
    DebugMessage(DEBUG_DETECT, "Checking bidirectional rule...\n");

    if (CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
        rtn_idx->flags, CHECK_SRC_IP | (check_ports ? CHECK_SRC_PORT : 0)))
    {
        DebugMessage(DEBUG_DETECT, "   Src->Src check passed\n");
        if (!CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_DST_IP | (check_ports ? CHECK_DST_PORT : 0)))
        {
            DebugMessage(DEBUG_DETECT,
                "   Dst->Dst check failed, checking inverse combination\n");
            if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
                rtn_idx->flags, (CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0))))
            {
                DebugMessage(DEBUG_DETECT,
                    "   Inverse Dst->Src check passed\n");
                if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
                    rtn_idx->flags, (CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0))))
                {
                    DebugMessage(DEBUG_DETECT,
                        "   Inverse Src->Dst check failed\n");
                    return 0;
                }
                else
                {
                    DebugMessage(DEBUG_DETECT, "Inverse addr/port match\n");
                }
            }
            else
            {
                DebugMessage(DEBUG_DETECT, "   Inverse Dst->Src check failed,"
                    " trying next rule\n");
                return 0;
            }
        }
        else
        {
            DebugMessage(DEBUG_DETECT, "dest IP/port match\n");
        }
    }
    else
    {
        DebugMessage(DEBUG_DETECT,
            "   Src->Src check failed, trying inverse test\n");
        if (CheckAddrPort(rtn_idx->dip, CHECK_ADDR_DST_ARGS(rtn_idx), p,
            rtn_idx->flags, CHECK_SRC_IP | INVERSE | (check_ports ? CHECK_SRC_PORT : 0)))
        {
            DebugMessage(DEBUG_DETECT,
                "   Dst->Src check passed\n");

            if (!CheckAddrPort(rtn_idx->sip, CHECK_ADDR_SRC_ARGS(rtn_idx), p,
                rtn_idx->flags, CHECK_DST_IP | INVERSE | (check_ports ? CHECK_DST_PORT : 0)))
            {
                DebugMessage(DEBUG_DETECT,
                    "   Src->Dst check failed\n");
                return 0;
            }
            else
            {
                DebugMessage(DEBUG_DETECT,
                    "Inverse addr/port match\n");
            }
        }
        else
        {
            DebugMessage(DEBUG_DETECT,"   Inverse test failed, "
                "testing next rule...\n");
            return 0;
        }
    }

    DebugMessage(DEBUG_DETECT,"   Bidirectional success!\n");
    return 1;
}

/****************************************************************************
 *
 * Function: CheckSrcIp(Packet *, RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the source IP and see if it equals the SIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckSrcIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckSrcIPEqual: ");

    if (!(rtn_idx->flags & EXCEPT_SRC_IP))
    {
        if ( sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src()) )
        {
            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any*
         * of the source addresses
         */
        DebugMessage(DEBUG_DETECT,"  global exception flag, \n");

        if ( sfvar_ip_in(rtn_idx->sip, p->ptrs.ip_api.get_src()) )
            return 0;

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }

    DebugMessage(DEBUG_DETECT,"  Mismatch on SIP\n");

    return 0;

    /* return 0 on a failed test */
    return 0;
}

/****************************************************************************
 *
 * Function: CheckDstIp(Packet *, RuleTreeNode *, RuleFpList *)
 *
 * Purpose: Test the dest IP and see if it equals the DIP of the packet
 *
 * Arguments: p => ptr to the decoded packet data structure
 *            rtn_idx => ptr to the current rule data struct
 *            fp_list => ptr to the current function pointer node
 *
 * Returns: 0 on failure (no match), 1 on success (match)
 *
 ***************************************************************************/
int CheckDstIP(Packet* p, RuleTreeNode* rtn_idx, RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT, "CheckDstIPEqual: ");

    if (!(rtn_idx->flags & EXCEPT_DST_IP))
    {
        if ( sfvar_ip_in(rtn_idx->dip, p->ptrs.ip_api.get_dst()) )
        {
            /* the packet matches this test, proceed to the next test */
            return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
        }
    }
    else
    {
        /* global exception flag is up, we can't match on *any*
         * of the source addresses */
        DebugMessage(DEBUG_DETECT,"  global exception flag, \n");

        if ( sfvar_ip_in(rtn_idx->dip, p->ptrs.ip_api.get_dst()) )
            return 0;

        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }

    return 0;
}

int CheckSrcPortEqual(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckSrcPortEqual: ");

    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( PortObjectHasPort(rtn_idx->src_portobject,p->ptrs.sp) )
    {
        DebugMessage(DEBUG_DETECT, "  SP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT, "   SP mismatch!\n");
    }

    return 0;
}

int CheckSrcPortNotEq(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckSrcPortNotEq: ");

    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( !PortObjectHasPort(rtn_idx->src_portobject,p->ptrs.sp) )
    {
        DebugMessage(DEBUG_DETECT, "  !SP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT, "  !SP mismatch!\n");
    }

    return 0;
}

int CheckDstPortEqual(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckDstPortEqual: ");

    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( PortObjectHasPort(rtn_idx->dst_portobject,p->ptrs.dp) )
    {
        DebugMessage(DEBUG_DETECT, " DP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT," DP mismatch!\n");
    }
    return 0;
}

int CheckDstPortNotEq(Packet* p, RuleTreeNode* rtn_idx,
    RuleFpList* fp_list, int check_ports)
{
    DebugMessage(DEBUG_DETECT,"CheckDstPortNotEq: ");

    /* Check if attributes provided match earlier */
    if (check_ports == 0)
    {
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    if ( !PortObjectHasPort(rtn_idx->dst_portobject,p->ptrs.dp) )
    {
        DebugMessage(DEBUG_DETECT, " !DP match!\n");
        return fp_list->next->RuleHeadFunc(p, rtn_idx, fp_list->next, check_ports);
    }
    else
    {
        DebugMessage(DEBUG_DETECT," !DP mismatch!\n");
    }

    return 0;
}

int RuleListEnd(Packet*, RuleTreeNode*, RuleFpList*, int)
{
    return 1;
}

int OptListEnd(void*, Cursor&, Packet*)
{
    return DETECTION_OPTION_MATCH;
}

