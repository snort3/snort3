//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
/*
**  Author(s):  Dan Roelker <droelker@sourcefire.com>
**              Marc Norton <mnorton@sourcefire.com>
**              Andrew R. Baker <andrewb@snort.org>
**              Andrew J. Mullican <amullican@sourcefire.com>
**              Steven Sturges <ssturges@sourcefire.com>
**  NOTES
**  5.15.02 - Initial Source Code. Norton/Roelker
**  2002-12-06 - Modify event selection logic to fix broken custom rule types
**               arbitrary rule type ordering (ARB)
**  2005-02-08 - Track alerts per session so that they aren't double reported
**               for rebuilt packets.  AJM.
**  2005-02-17 - Track alerts per IP frag tracker so that they aren't double
**               reported for rebuilt frags.  SAS (code similar to AJM's for
**               per session tracking).
**
*/

#include "fp_detect.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>

#include "detect.h"
#include "fp_config.h"
#include "fp_create.h"
#include "service_map.h"
#include "detection_util.h"
#include "detection_options.h"
#include "pattern_match_data.h"
#include "pcrm.h"
#include "tag.h"
#include "rules.h"
#include "treenodes.h"

#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "framework/cursor.h"
#include "framework/inspector.h"
#include "framework/ips_action.h"
#include "framework/mpse.h"
#include "filters/sfthreshold.h"
#include "filters/rate_filter.h"
#include "events/event_wrapper.h"
#include "packet_io/active.h"
#include "parser/parser.h"
#include "utils/sflsq.h"
#include "utils/util.h"
#include "profiler/profiler.h"
#include "actions/actions.h"
#include "sfip/sf_ip.h"
#include "managers/action_manager.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "search_engines/pat_stats.h"
#include "stream/stream.h"
#include "utils/stats.h"

#include "tics/tics.h"

THREAD_LOCAL ProfileStats rulePerfStats;
THREAD_LOCAL ProfileStats ruleRTNEvalPerfStats;
THREAD_LOCAL ProfileStats ruleOTNEvalPerfStats;
THREAD_LOCAL ProfileStats ruleNFPEvalPerfStats;

THREAD_LOCAL uint64_t rule_eval_pkt_count = 0;

static THREAD_LOCAL OTNX_MATCH_DATA t_omd;

#ifdef TICS_USE_RXP_MATCH
THREAD_LOCAL int PM_TYPE_search = PM_TYPE_MAX;
THREAD_LOCAL int port_group_search = 0;
#endif

/* initialize the global OTNX_MATCH_DATA variable */
void otnx_match_data_init(int num_rule_types)
{
    t_omd.iMatchInfoArraySize = num_rule_types;
    t_omd.matchInfo = (MATCH_INFO*)snort_calloc(num_rule_types, sizeof(MATCH_INFO));
}

void otnx_match_data_term()
{
    if ( t_omd.matchInfo )
        snort_free(t_omd.matchInfo);

    t_omd.matchInfo = nullptr;
}

// Initialize the OTNX_MATCH_DATA structure.  We do this for
// every packet so this only sets the necessary counters to
// zero which saves us time.

static inline void InitMatchInfo(OTNX_MATCH_DATA* o)
{
    for ( int i = 0; i < o->iMatchInfoArraySize; i++ )
        o->matchInfo[i].iMatchCount = 0;

    o->have_match = false;
}

// called by fpLogEvent(), which does the filtering etc.
// this handles the non-rule-actions (responses).
static inline void fpLogOther(
    Packet* p, const RuleTreeNode* rtn, const OptTreeNode* otn, int action)
{
    if ( EventTrace_IsEnabled() )
        EventTrace_Log(p, otn, action);

    // rule option actions are queued here (eg replace)
    otn_trigger_actions(otn, p);

    // rule actions are queued here (eg reject)
    if ( rtn->listhead->action )
        ActionManager::queue(rtn->listhead->action);
}

/*
**    This function takes the corresponding RTN and OTN for a snort rule
**    and logs the event and packet that was alerted upon.  This
**    function was pulled out of fpEvalSomething, so now we can log an
**    event no matter where we are.
*/
int fpLogEvent(const RuleTreeNode* rtn, const OptTreeNode* otn, Packet* p)
{
    int action = -1, rateAction = -1;
    int override, filterEvent = 0;

    if ( pass_action(rtn->type) )
        p->packet_flags |= PKT_PASS_RULE;

    if ( otn->stateless )
    {
        /* Stateless rule, set the stateless bit */
        p->packet_flags |= PKT_STATELESS;
    }
    else
    {
        /* Not stateless, clear the stateless bit if it was set
         * from a previous rule.
         */
        p->packet_flags &= ~PKT_STATELESS;
    }

    if ((p->packet_flags & PKT_STREAM_UNEST_UNI) &&
        SnortConfig::assure_established() &&
        (!(p->packet_flags & PKT_REBUILT_STREAM)) &&
        (otn->stateless == 0))
    {
        // We still want to drop packets that are drop rules.
        // We just don't want to see the alert.
        action_apply(rtn->type, p);
        fpLogOther(p, rtn, otn, rtn->type);
        return 1;
    }

    // perform rate filtering tests - impacts action taken
    rateAction = RateFilter_Test(otn, p);
    override = ( rateAction >= RULE_TYPE__MAX );
    if ( override )
        rateAction -= RULE_TYPE__MAX;

    // internal events are no-ops
    if ( (rateAction < 0) && EventIsInternal(otn->sigInfo.generator) )
    {
        return 1;
    }
    action = (rateAction < 0) ? (int)rtn->type : rateAction;

    // When rate filters kick in, event filters are still processed.
    // perform event filtering tests - impacts logging
    if ( p->ptrs.ip_api.is_valid() )
    {
        filterEvent = sfthreshold_test(
            otn->sigInfo.generator,
            otn->sigInfo.id,
            p->ptrs.ip_api.get_src(), p->ptrs.ip_api.get_dst(),
            p->pkth->ts.tv_sec);
    }
    else
    {
        sfip_t cleared;
        sfip_clear(cleared);

        filterEvent = sfthreshold_test(
            otn->sigInfo.generator,
            otn->sigInfo.id,
            &cleared, &cleared,
            p->pkth->ts.tv_sec);
    }

    if ( (filterEvent < 0) || (filterEvent > 0 && !override) )
    {
        /*
        **  If InlineMode is on, then we still want to drop packets
        **  that are drop rules.  We just don't want to see the alert.
        */
        action_apply((RuleType)action, p);
        fpLogOther(p, rtn, otn, action);
        pc.event_limit++;
        return 1;
    }

    /* If this packet has been passed based on detection rules,
     * check the decoder/preprocessor events (they have been added to Event queue already).
     * If its order is lower than 'pass', it should have been passed.
     * This is consistent with other detection rules */
    if ( (p->packet_flags & PKT_PASS_RULE)
        &&(SnortConfig::get_eval_index(rtn->type) > SnortConfig::get_eval_index(RULE_TYPE__PASS)))
    {
        fpLogOther(p, rtn, otn, rtn->type);
        return 1;
    }

    otn->state[get_instance_id()].alerts++;

    event_id++;
    action_execute((RuleType)action, p, otn, event_id);
    fpLogOther(p, rtn, otn, action);

    return 0;
}

/*
**
**  NAME
**    fpAddMatch::
**
**  DESCRIPTION
**    Add and Event to the appropriate Match Queue: Alert, Pass, or Log.
**    This allows us to find multiple events per packet and pick the 'best'
**    one.  This function also allows us to change the order of alert,
**    pass, and log signatures by cacheing them for decision later.
**
**    IMPORTANT NOTE:
**    fpAddMatch must be called even when the queue has been maxed
**    out.  This is because there are three different queues (alert,
**    pass, log) and unless all three are filled (or at least the
**    queue that is in the highest priority), events must be looked
**    at to see if they are members of a queue that is not maxed out.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA    * - the omd to add the event to.
**    int pLen             - length of pattern that matched, 0 for no content
**    OptTreeNode        * - the otn to add.
**
**  FORMAL OUTPUTS
**    int - 1 max_events variable hit, 0 successful.
**
*/
int fpAddMatch(OTNX_MATCH_DATA* omd_local, int /*pLen*/, const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);
    int evalIndex = rtn->listhead->ruleListNode->evalIndex;

    /* bounds check index */
    if ( evalIndex >= omd_local->iMatchInfoArraySize )
    {
        pc.match_limit++;
        return 1;
    }
    MATCH_INFO* pmi = &omd_local->matchInfo[evalIndex];

    /*
    **  If we hit the max number of unique events for any rule type alert,
    **  log or pass, then we don't add it to the list.
    */
    if ( pmi->iMatchCount >= (int)snort_conf->fast_pattern_config->get_max_queue_events() ||
        pmi->iMatchCount >= MAX_EVENT_MATCH)
    {
        pc.match_limit++;
        return 1;
    }

    // don't store the same otn again
    for ( int i=0; i< pmi->iMatchCount; i++ )
    {
        if ( pmi->MatchArray[ i  ] == otn )
            return 0;
    }

    //  add the event to the appropriate list
    pmi->MatchArray[ pmi->iMatchCount ] = otn;

    pmi->iMatchCount++;
    omd_local->have_match = true;
    return 0;
}

/*
**
**  NAME
**    fpEvalRTN::
**
**  DESCRIPTION
**    Evaluates an RTN against a packet.  We can probably get rid of
**    the check_ports variable, but it's in there for good luck.  :)
**
**  FORMAL INPUTS
**    RuleTreeNode * - RTN to check packet against.
**    Packet       * - Packet to evaluate
**    int            - whether to do a quick enhancement against ports.
**
**  FORMAL OUTPUT
**    int - 1 if match, 0 if match failed.
**
*/
int fpEvalRTN(RuleTreeNode* rtn, Packet* p, int check_ports)
{
    Profile rule_profile(rulePerfStats);
    Profile rule_rtn_eval_profile(ruleRTNEvalPerfStats);

    if ( !rtn )
        return 0;

    // FIXIT-L maybe add a port test here ...

    DebugFormat(DEBUG_DETECT, "[*] Rule Head %p\n", (void*) rtn);

    if (!rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func, check_ports))
    {
        DebugMessage(DEBUG_DETECT,
            "   => Header check failed, checking next node\n");
        DebugMessage(DEBUG_DETECT,
            "   => returned from next node check\n");
        return 0;
    }

    DebugMessage(DEBUG_DETECT,
        "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
    DebugFormat(DEBUG_DETECT, "   => RTN %p Matched!\n", (void*) rtn);
    DebugMessage(DEBUG_DETECT,
        "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");
    /*
    **  Return that there is a rule match and log the event outside
    **  of this routine.
    */
    return 1;
}

static int detection_option_tree_evaluate(detection_option_tree_root_t* root,
    detection_option_eval_data_t* eval_data)
{
    if ( !root )
        return 0;

    RuleLatency::Context rule_latency_ctx(root);

    if ( RuleLatency::suspended() )
        return 0;

    Cursor c(eval_data->p);
    int rval = 0;

    for ( int i = 0; i < root->num_children; ++i )
    {
        // Increment number of events generated from that child 
        rval += detection_option_node_evaluate(root->children[i], eval_data, c);
    }

    return rval;
}

static int rule_tree_match(
    void* user, void* tree, int index, void* context, void* neg_list)
{
    PMX* pmx = (PMX*)user;
    OTNX_MATCH_DATA* pomd = (OTNX_MATCH_DATA*)context;

    detection_option_tree_root_t* root = (detection_option_tree_root_t*)tree;
    detection_option_eval_data_t eval_data;
    NCListNode* ncl;

    eval_data.pomd = pomd;
    eval_data.p = pomd->p;
    eval_data.pmd = pmx->pmd;
    eval_data.flowbit_failed = 0;
    eval_data.flowbit_noalert = 0;

    {
        Profile rule_profile(rulePerfStats);
        /* NOTE: The otn will be the first one in the match state. If there are
         * multiple rules associated with a match state, mucking with the otn
         * may muck with an unintended rule */

        /* Set flag for not contents so they aren't evaluated */
        for (ncl = (NCListNode*)neg_list; ncl != nullptr; ncl = ncl->next)
        {
            PMX* neg_pmx = (PMX*)ncl->pmx;
            assert(neg_pmx->pmd->last_check);

            PmdLastCheck* last_check =
                neg_pmx->pmd->last_check + get_instance_id();

            last_check->ts.tv_sec = eval_data.p->pkth->ts.tv_sec;
            last_check->ts.tv_usec = eval_data.p->pkth->ts.tv_usec;
            last_check->packet_number = (rule_eval_pkt_count
                + (PacketManager::get_rebuilt_packet_count()));
            last_check->rebuild_flag = (eval_data.p->packet_flags & PKT_REBUILT_STREAM);
        }

        int ret = 0;
        {
            Profile rule_otn_eval_profile(ruleOTNEvalPerfStats);
            ret = detection_option_tree_evaluate(root, &eval_data);
        }

        if ( ret )
        {
            //  We have a qualified event from this tree
            pomd->pg->event_count++;
            pmqs.qualified_events++;
        }
        else
        {
            // This means that the event is non-qualified.
            pomd->pg->match_count++;
            pmqs.non_qualified_events++;
        }
    }

    if (eval_data.flowbit_failed)
        return -1;

    /* If this is for an IP rule set, evalute the rules from
     * the inner IP offset as well */
    if (eval_data.p->packet_flags & PKT_IP_RULE)
    {
        ip::IpApi tmp_api = eval_data.p->ptrs.ip_api;
        int8_t curr_layer = eval_data.p->num_layers - 1;

        if (layer::set_inner_ip_api(eval_data.p,
            eval_data.p->ptrs.ip_api,
            curr_layer) &&
            (eval_data.p->ptrs.ip_api != tmp_api))
        {
            const uint8_t* tmp_data = eval_data.p->data;
            uint16_t tmp_dsize = eval_data.p->dsize;

            /* clear so we dont keep recursing */
            eval_data.p->packet_flags &= ~PKT_IP_RULE;
            eval_data.p->packet_flags |= PKT_IP_RULE_2ND;

            do
            {
                eval_data.p->data = eval_data.p->ptrs.ip_api.ip_data();
                eval_data.p->dsize = eval_data.p->ptrs.ip_api.pay_len();

                /* Recurse, and evaluate with the inner IP */
                rule_tree_match(user, tree, index, context, nullptr);
            }
            while (layer::set_inner_ip_api(eval_data.p,
                eval_data.p->ptrs.ip_api,
                curr_layer) &&
                (eval_data.p->ptrs.ip_api != tmp_api));

            /*  cleanup restore original data & dsize */
            eval_data.p->packet_flags &= ~PKT_IP_RULE_2ND;
            eval_data.p->packet_flags |= PKT_IP_RULE;

            eval_data.p->data = tmp_data;
            eval_data.p->dsize = tmp_dsize;
        }
    }
    return 0;
}

static int sortOrderByPriority(const void* e1, const void* e2)
{
    OptTreeNode* otn1;
    OptTreeNode* otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode**)e1;
    otn2 = *(OptTreeNode**)e2;

    if ( otn1->sigInfo.priority < otn2->sigInfo.priority )
        return -1;

    if ( otn1->sigInfo.priority > otn2->sigInfo.priority )
        return +1;

    /* This improves stability of repeated tests */
    if ( otn1->sigInfo.id < otn2->sigInfo.id )
        return -1;

    if ( otn1->sigInfo.id > otn2->sigInfo.id )
        return +1;

    return 0;
}

static int sortOrderByContentLength(const void* e1, const void* e2)
{
    OptTreeNode* otn1;
    OptTreeNode* otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode**)e1;
    otn2 = *(OptTreeNode**)e2;

    if (otn1->longestPatternLen < otn2->longestPatternLen)
        return +1;

    if (otn1->longestPatternLen > otn2->longestPatternLen)
        return -1;

    /* This improves stability of repeated tests */
    if ( otn1->sigInfo.id < otn2->sigInfo.id )
        return +1;

    if ( otn1->sigInfo.id > otn2->sigInfo.id )
        return -1;

    return 0;
}

/*
**
**  NAME
**    fpAddSessionAlert::
**
**  DESCRIPTION
**    This function flags an alert per session.
**
**  FORMAL INPUTS
**    Packet *      - the packet to inspect
**    OptTreeNode * - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if not flagged
**          1 if flagged
**
*/
static inline int fpAddSessionAlert(Packet* p, const OptTreeNode* otn)
{
    if ( !p->flow )
        return 0;

    if ( !otn )
        return 0;

    return !Stream::add_flow_alert(
        p->flow, p, otn->sigInfo.generator, otn->sigInfo.id);
}

/*
**
**  NAME
**    fpSessionAlerted::
**
**  DESCRIPTION
**    This function indicates whether or not an alert has been generated previously
**    in this session, but only if this is a rebuilt packet.
**
**  FORMAL INPUTS
**    Packet *      - the packet to inspect
**    OptTreeNode * - the rule that generated the alert
**
**  FORMAL OUTPUTS
**    int - 0 if alert NOT previously generated
**          1 if alert previously generated
**
*/
static inline int fpSessionAlerted(Packet* p, const OptTreeNode* otn)
{
    const SigInfo* si = &otn->sigInfo;

    if (!Stream::check_flow_alerted(p->flow, p, si->generator, si->id))
        return 0;
    else
        return 1;
}

/*
**
**  NAME
**    fpFinalSelectEvent::
**
**  DESCRIPTION
**    fpFinalSelectEvent is called at the end of packet processing
**    to decide, if there hasn't already been a selection, to decide
**    what event to select.  This function is different from
**    fpSelectEvent by the fact that fpSelectEvent only selects an
**    event if it is the first priority setting (drop/pass/alert...).
**
**    We also loop through the events we log, so that we don't log the
**    same event twice.  This can happen with unique conflicts some
**    of the time.
**
**    IMPORTANT NOTE:
**    We call fpFinalSelectEvent() after all processing of the packet
**    has been completed.  The reason this must be called afterwards is
**    because of unique rule group conflicts for a packet.  If there is
**    a unique conflict, then we inspect both rule groups and do the final
**    event select after both rule groups have been inspected.  The
**    problem came up with bi-directional rules with pass rule ordering
**    as the first type of rule.  Before we would detect a alert rule in
**    the first rule group, and since there was no pass rules we would
**    log that alert rule.  However, if we had inspected the second rule
**    group, we would have found a pass rule and that should have taken
**    precedence.  We now inspect both rule groups before doing a final
**    event select.
**
**    NOTES
**    Jan 2006 : marc norton
**    Previously it was possible to not log all desired events, if for
**    instance the rule order was alert->drop in inline mode we would
**    alert but no drop.  The default ordering of 'drop alert pass log ...'
**    normally handles this, however, it could happen.  Also, in the
**    default ordering alerts on the same packet a drop was applied to
**    did not get logged. To be more flexible and handle all manners of
**    subjective rule ordering and logging desired by the whole farm we've
**    changed things a bit.
**
**    Now, each actions event list is processed in order, based on the rule
**    order.  We process all events up to the log limit specified via the
**    'config event_queue: ...' as you might expect.  Pass rules are
**    handled a bit differently. As soon as a pass rule based event is
**    processed in the event queue, we stop processing any further events
**    on the packet if the pass event is the 1st ordering that sees an
**    event.  Otherwise if the ordering has it that pass rule events are
**    processed after a drop or alert you will see the drops and alerts,
**    and the pass event just causes us to stop processing any more events
**    on the packet, but the packet does not pass.  Also, the --alert-on-drop
**    flag causes any drop/sdrop/reject rules to be loaded as alert rules.
**    The default has been to ignore them on parsing.
**
**    If this is less than clear, herese the $.02 version:
**    default order -> pass drop alert log ( --alert-before-pass reverts
**    to -> drop alert pass log ) the 1st action-type of events in the rule
**    ordering to be seen gets logged by default the --flush-all-events
**    flag will cause secondary and tertiary action-events to be logged.
**    the -o flag is useless, but accepted, for now.
**    the max_events and log fields are reduced to only needing the log
**    events field. max_fields is harmless.
**    ( drop rules may be honored as alerts in IDS mode (no -Q) by using
**    the --alert-on-drop flag )
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - omd to select event from.
**    Packet *          - pointer to packet to log.
**
**  FORMAL OUTPUT
**    int - return 0 if no match, 1 if match.
**
*/
static inline int fpFinalSelectEvent(OTNX_MATCH_DATA* o, Packet* p)
{
    if ( !o->have_match )
        return 0;

    int i;
    int j;
    int k;
    const OptTreeNode* otn;
    int tcnt = 0;
    EventQueueConfig* eq = snort_conf->event_queue_config;
    RuleTreeNode* rtn;

    for ( i = 0; i < o->iMatchInfoArraySize; i++ )
    {
        /* bail if were not dumping events in all the action groups,
         * and we've alresady got some events */
        if (!SnortConfig::process_all_events() && (tcnt > 0))
            return 1;

        if (o->matchInfo[i].iMatchCount)
        {
            /*
             * We must always sort so if we que 8 and log 3 and they are
             * all from the same action group we want them sorted so we get
             * the highest 3 in priority, priority and lenght sort do NOT
             * take precedence over 'alert drop pass ...' ordering.  If
             * order is 'drop alert', and we log 3 for drop alertsdo not
             * get logged.  IF order is 'alert drop', and we log 3 for
             * alert, than no drops are logged.  So, there should be a
             * built in drop/sdrop/reject comes before alert/pass/log as
             * part of the natural ordering....Jan '06..
             */
            /* Sort the rules in this action group */
            if (eq->order == SNORT_EVENTQ_PRIORITY)
            {
                qsort(o->matchInfo[i].MatchArray, o->matchInfo[i].iMatchCount,
                    sizeof(void*), sortOrderByPriority);
            }
            else if (eq->order == SNORT_EVENTQ_CONTENT_LEN)
            {
                qsort(o->matchInfo[i].MatchArray, o->matchInfo[i].iMatchCount,
                    sizeof(void*), sortOrderByContentLength);
            }
            else
            {
                FatalError("fpdetect: Order function for event queue is invalid.\n");
            }

            /* Process each event in the action (alert,drop,log,...) groups */
            for (j=0; j < o->matchInfo[i].iMatchCount; j++)
            {
                otn = o->matchInfo[i].MatchArray[j];
                rtn = getRtnFromOtn(otn);

                if (otn && rtn && pass_action(rtn->type))
                {
                    /* Already acted on rules, so just don't act on anymore */
                    if ( tcnt > 0 )
                        return 1;
                }

                /*
                **  Loop here so we don't log the same event
                **  multiple times.
                */
                for (k = 0; k < j; k++)
                {
                    if (o->matchInfo[i].MatchArray[k] == otn)
                    {
                        otn = nullptr;
                        break;
                    }
                }

                if ( otn && !fpSessionAlerted(p, otn) )
                {
                    /*
                    **  QueueEvent
                    */
                    if ( SnortEventqAdd(otn) )
                        pc.queue_limit++;

                    tcnt++;
                }
                else
                    pc.alert_limit++;

                /* Only count it if we're going to log it */
                if (tcnt <= eq->log_events)
                {
                    if ( p->flow )
                        fpAddSessionAlert(p, otn);
                }

                if (tcnt >= eq->max_events)
                {
                    pc.queue_limit++;
                    return 1;
                }

                /* only log/count one pass */
                if ( otn && rtn && pass_action(rtn->type))
                {
                    p->packet_flags |= PKT_PASS_RULE;
                    return 1;
                }
            }
        }
    }

    return 0;
}

class MpseStash
{
public:
    static const unsigned max = 32;

    void init()
    { count = flushed = 0; }

    bool push(void* user, void* tree, int index, void* list);
    bool process(MpseMatch, void*);

private:
    unsigned count;
    unsigned flushed;

    struct Node {
        void* user;
        void* tree;
        void* list;
        int index;
    } queue[max];
};

static THREAD_LOCAL MpseStash stash;

// uniquely insert into q, should splay elements for performance
// return true if maxed out to trigger a flush
bool MpseStash::push(void* user, void* tree, int index, void* list)
{
    pmqs.tot_inq_inserts++;

    for ( int i = (int)(count) - 1; i >= 0; --i )
    {
        if ( tree == queue[i].tree )
            return false;
    }

    if ( count < max )
    {
        Node& node = queue[count++];
        node.user = user;
        node.tree = tree;
        node.index = index;
        node.list = list;
        pmqs.tot_inq_uinserts++;
    }

    if ( count == max )
    {
        flushed++;
        return true;
    }

    return false;
}

bool MpseStash::process(MpseMatch match, void* context)
{
    if ( count > pmqs.max_inq )
        pmqs.max_inq = count;

    pmqs.tot_inq_flush += flushed;

    for ( unsigned i = 0; i < count; ++i )
    {
        Node& node = queue[i];

        // process a pattern - case is handled by otn processing
        int res = match(node.user, node.tree, node.index, context, node.list);

        if ( res > 0 )
        {
            /* terminate matching */
            count = 0;
            return true;
        }
    }
    count = 0;
    return false;
}

// rule_tree_match() could be used instead to bypass the queuing
static int rule_tree_queue(
    void* user, void* tree, int index, void* context, void* list)
{
    if ( stash.push(user, tree, index, list) )
    {
        if ( stash.process(rule_tree_match, context) )
        {
            return 1;
        }
    }
    return 0;
}

#define SEARCH_DATA(buf, len, cnt) \
    { \
        assert(so->get_pattern_count() > 0); \
        int start_state = 0; \
        cnt++; \
        omd->data = buf; omd->size = len; \
        stash.init(); \
        so->search(buf, len, rule_tree_queue, omd, &start_state); \
        stash.process(rule_tree_match, omd); \
        if ( PacketLatency::fastpath() ) \
            return 1; \
    }

#define SEARCH_BUFFER(ibt, pmt, cnt) \
    if ( gadget->get_fp_buf(ibt, p, buf) ) \
    { \
        if ( Mpse* so = port_group->mpse[pmt] ) \
            SEARCH_DATA(buf.data, buf.len, cnt) \
    }

static int fp_search(
    PortGroup* port_group, Packet* p,
    int check_ports, int type, OTNX_MATCH_DATA* omd)
{
    Inspector* gadget = p->flow ? p->flow->gadget : nullptr;
    InspectionBuffer buf;

    omd->pg = port_group;
    omd->p = p;
    omd->check_ports = check_ports;

    bool user_mode = snort_conf->sopgTable->user_mode;

    if ( (!user_mode or type < 2) and p->data and p->dsize )
    {
        // ports search raw packet only
        if ( Mpse* so = port_group->mpse[PM_TYPE_PKT] )
        {
            uint16_t pattern_match_size = p->dsize;

            if ( IsLimitedDetect(p) && (p->alt_dsize < p->dsize) )
                pattern_match_size = p->alt_dsize;

            if ( pattern_match_size )
            {
#ifdef TICS_USE_RXP_MATCH
                PM_TYPE_search = PM_TYPE_PKT;
#endif /* TICS_USE_RXP_MATCH */

                SEARCH_DATA(p->data, pattern_match_size, pc.pkt_searches);
            }

            if ( pattern_match_size )
                p->is_cooked() ?  pc.cooked_searches++ : pc.raw_searches++;
        }
    }

    if ( (!user_mode or type == 1) and gadget )
    {
        // service searches PDU buffers and file
#ifdef TICS_USE_RXP_MATCH
        PM_TYPE_search = PM_TYPE_KEY;
#endif /* TICS_USE_RXP_MATCH */

        SEARCH_BUFFER(buf.IBT_KEY, PM_TYPE_KEY, pc.key_searches);

#ifdef TICS_USE_RXP_MATCH
        PM_TYPE_search = PM_TYPE_HEADER;
#endif /* TICS_USE_RXP_MATCH */

        SEARCH_BUFFER(buf.IBT_HEADER, PM_TYPE_HEADER, pc.header_searches);

#ifdef TICS_USE_RXP_MATCH
        PM_TYPE_search = PM_TYPE_BODY;
#endif /* TICS_USE_RXP_MATCH */

        SEARCH_BUFFER(buf.IBT_BODY, PM_TYPE_BODY, pc.body_searches);

        // FIXIT-L PM_TYPE_ALT will never be set unless we add
        // norm_data keyword or telnet, rpc_decode, smtp keywords
        // until then we must use the standard packet mpse
#ifdef TICS_USE_RXP_MATCH
        PM_TYPE_search = PM_TYPE_ALT;
#endif /* TICS_USE_RXP_MATCH */

        SEARCH_BUFFER(buf.IBT_ALT, PM_TYPE_PKT, pc.alt_searches);
    }

    if ( !user_mode or type > 0 )
    {
        // file searches file only
        if ( Mpse* so = port_group->mpse[PM_TYPE_FILE] )
        {
            // FIXIT-M file data should be obtained from
            // inspector gadget as is done with SEARCH_BUFFER
            if ( g_file_data.len )
            {
#ifdef TICS_USE_RXP_MATCH
                PM_TYPE_search = PM_TYPE_FILE;
#endif /* TICS_USE_RXP_MATCH */

                SEARCH_DATA(g_file_data.data, g_file_data.len, pc.file_searches);
            }
        }
    }
    return 0;
}

/*
**
**  NAME
**    fpEvalHeaderSW::
**
**  DESCRIPTION
**    This function does a set-wise match on content, and walks an otn list
**    for non-content.  The otn list search will eventually be redone for
**    for performance purposes.
**
**  FORMAL INPUTS
**    PortGroup * - the port group to inspect
**    Packet *     - the packet to inspect
**    int          - whether src/dst ports should be checked (udp/tcp or icmp)
**    char         - whether the rule is an IP rule (change the packet payload pointer)
**
**  FORMAL OUTPUTS
**    int - 0 for failed pattern match
**          1 for sucessful pattern match
**
*/
static inline int fpEvalHeaderSW(PortGroup* port_group, Packet* p,
    int check_ports, char ip_rule, int type, OTNX_MATCH_DATA* omd)
{
    const uint8_t* tmp_payload;
    int8_t curr_ip_layer = 0;
    bool repeat = false;
    uint16_t tmp_dsize;
    FastPatternConfig* fp = snort_conf->fast_pattern_config;

    if (ip_rule)
    {
        tmp_payload = p->data;
        tmp_dsize = p->dsize;

        if (layer::set_outer_ip_api(p, p->ptrs.ip_api, curr_ip_layer))
        {
            p->data = p->ptrs.ip_api.ip_data();
            p->dsize = p->ptrs.ip_api.pay_len();
            p->packet_flags |= PKT_IP_RULE;
            repeat = true;
        }
    }
    else
    {
        p->packet_flags &= ~PKT_IP_RULE;
    }

    if ( do_detect_content )
    {
        if ( fp->get_stream_insert() || !(p->packet_flags & PKT_STREAM_INSERT) )
            if ( fp_search(port_group, p, check_ports, type, omd) )
                return 0;
    }

    do
    {
        // FIXIT-L restrict no-fast-pattern to non-data packets?  (non-data includes
        // defrags).  strictly speaking, nfp (no fast pattern) rules are not the same
        // as nc (no content).  since these rules may have content, they must be run
        // against all packets.
        //if ( p->is_data() )
        //    break;

        if (port_group->nfp_rule_count)
        {
            // walk and test the nfp OTNs
            if ( fp->get_debug_print_nc_rules() )
                LogMessage("NC-testing %u rules\n", port_group->nfp_rule_count);

            detection_option_eval_data_t eval_data;

            eval_data.pomd = omd;
            eval_data.p = p;
            eval_data.pmd = nullptr;
            eval_data.flowbit_failed = 0;
            eval_data.flowbit_noalert = 0;

            int rval = 0;
            {
                Profile rule_profile(rulePerfStats);
                Profile rule_nfp_eval_profile(ruleNFPEvalPerfStats);
                rval = detection_option_tree_evaluate(
                    (detection_option_tree_root_t*)port_group->nfp_tree, &eval_data);
            }

            if (rval)
            {
                // We have a qualified event from this tree
                port_group->event_count++;
                pmqs.qualified_events++;
            }
            else
            {
                // This means that the event is non-qualified.
                port_group->match_count++;
                pmqs.non_qualified_events++;
            }
            pc.slow_searches++;
        }

        // FIXIT-L need to eval all IP layers, etc.
        // FIXIT-L why run only nfp rules?
        if (ip_rule)
        {
            /* Evaluate again with the next IP layer */
            if (layer::set_outer_ip_api(p, p->ptrs.ip_api, curr_ip_layer))
            {
                p->data = p->ptrs.ip_api.ip_data();
                p->dsize = p->ptrs.ip_api.pay_len();
                p->packet_flags |= PKT_IP_RULE_2ND | PKT_IP_RULE;
            }
            else
            {
                /* Set the data & dsize back to original values. */
                p->data = tmp_payload;
                p->dsize = tmp_dsize;
                p->packet_flags &= ~(PKT_IP_RULE| PKT_IP_RULE_2ND);
                repeat = false;
            }
        }
    }
    while (repeat);

    return 0;
}

static inline void fpEvalHeaderIp(Packet* p, OTNX_MATCH_DATA* omd)
{
    PortGroup* any = nullptr, * ip_group = nullptr;

    if ( !prmFindRuleGroupIp(snort_conf->prmIpRTNX, ANYPORT, &ip_group, &any) )
        return;

    if ( snort_conf->fast_pattern_config->get_debug_print_nc_rules() )
        LogMessage("fpEvalHeaderIp: ip_group=%p, any=%p\n", (void*)ip_group, (void*)any);

    if ( ip_group )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_IP_GROUP;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(ip_group, p, 0, 1, 0, omd);
    }

    if  (any )
    {
    #ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_ANY;
    #endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(any, p, 0, 1, 0, omd);
    }
}

static inline void fpEvalHeaderIcmp(Packet* p, OTNX_MATCH_DATA* omd)
{
    PortGroup* any = nullptr, * type = nullptr;

    if ( !prmFindRuleGroupIcmp(snort_conf->prmIcmpRTNX, p->ptrs.icmph->type, &type, &any) )
        return;

    if ( type )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_TYPE;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(type, p, 0, 0, 0, omd);
    }

    if ( any )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_ANY;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(any, p, 0, 0, 0, omd);
    }
}

static inline void fpEvalHeaderTcp(Packet* p, OTNX_MATCH_DATA* omd)
{
    PortGroup* src = nullptr, * dst = nullptr, * any = nullptr;

    if ( !prmFindRuleGroupTcp(snort_conf->prmTcpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &any) )
        return;

    DebugFormat(DEBUG_ATTRIBUTE,
        "fpEvalHeaderTcp: sport=%d, dport=%d, src:%p, dst:%p, any:%p\n",
        p->ptrs.sp,p->ptrs.dp,(void*)src,(void*)dst,(void*)any);

    if ( dst )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_DST;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(dst, p, 1, 0, 0, omd);
    }

    if ( src )
    {
        #ifdef TICS_USE_RXP_MATCH
            port_group_search = TICS_PORT_GROUP_SRC;
        #endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(src, p, 1, 0, 0, omd);
    }

    if ( any )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_ANY;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(any, p, 1, 0, 0, omd);
    }
}

static inline void fpEvalHeaderUdp(Packet* p, OTNX_MATCH_DATA* omd)
{
    PortGroup* src = nullptr, * dst = nullptr, * any = nullptr;

    if ( !prmFindRuleGroupUdp(snort_conf->prmUdpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &any) )
        return;

    DebugFormat(DEBUG_ATTRIBUTE,
        "fpEvalHeaderUdp: sport=%d, dport=%d, src:%p, dst:%p, any:%p\n",
        p->ptrs.sp,p->ptrs.dp,(void*)src,(void*)dst,(void*)any);

    if ( dst )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_DST;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(dst, p, 1, 0, 0, omd) ;
    }

    if ( src )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_SRC;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(src, p, 1, 0, 0, omd) ;
    }

    if ( any )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_ANY;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(any, p, 1, 0, 0, omd) ;
    }
}

static inline bool fpEvalHeaderSvc(Packet* p, OTNX_MATCH_DATA* omd, int proto)
{
    PortGroup* svc = nullptr, * file = nullptr;

    int16_t proto_ordinal = p->get_application_protocol();

    DebugFormat(DEBUG_ATTRIBUTE, "proto_ordinal=%d\n", proto_ordinal);

    if (proto_ordinal > 0)
    {
        if (p->is_from_server()) /* to cli */
        {
            DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_server\n");

            svc = snort_conf->sopgTable->get_port_group(proto, false, proto_ordinal);
            file = snort_conf->sopgTable->get_port_group(proto, false, SNORT_PROTO_FILE);
        }

        if (p->is_from_client()) /* to srv */
        {
            DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_client\n");

            svc = snort_conf->sopgTable->get_port_group(proto, true, proto_ordinal);
            file = snort_conf->sopgTable->get_port_group(proto, true, SNORT_PROTO_FILE);
        }

        DebugFormat(DEBUG_ATTRIBUTE,
            "fpEvalHeaderSvc:targetbased-ordinal-lookup: "
            "sport=%d, dport=%d, proto_ordinal=%d, proto=%d, src:%p, "
            "file:%p\n",p->ptrs.sp,p->ptrs.dp,proto_ordinal,proto,(void*)svc,(void*)file);
    }
    // FIXIT-P put alert service rules with file data fp in alert file group and
    // verfiy ports and service during rule eval to avoid searching file data 2x.
    int check_ports = (proto == SNORT_PROTO_USER) ? 2 : 1;

    if ( file )
    {
        #ifdef TICS_USE_RXP_MATCH
            port_group_search = TICS_PORT_GROUP_FILE;
        #endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(file, p, check_ports, 0, 2, omd);
    }

    if ( svc )
    {
#ifdef TICS_USE_RXP_MATCH
        port_group_search = TICS_PORT_GROUP_SVC;
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSW(svc, p, check_ports, 0, 1, omd);
    }

    return svc != nullptr;
}

static void fpEvalPacketUdp(Packet* p)
{
    OTNX_MATCH_DATA* omd = &t_omd;

    uint16_t tmp_sp = p->ptrs.sp;
    uint16_t tmp_dp = p->ptrs.dp;
    const udp::UDPHdr* tmp_udph = p->ptrs.udph;
    const uint8_t* tmp_data = p->data;
    uint16_t tmp_dsize = p->dsize;

    const udp::UDPHdr* udph = layer::get_outer_udp_lyr(p);

    p->ptrs.udph = udph;
    p->ptrs.sp = ntohs(udph->uh_sport);
    p->ptrs.dp = ntohs(udph->uh_dport);
    p->data = (const uint8_t*)udph + udp::UDP_HEADER_LEN;

    ip::IpApi tmp_api;
    int8_t curr_layer = 0;
    layer::set_outer_ip_api(p, tmp_api, curr_layer);

    if (tmp_api.pay_len() >  udp::UDP_HEADER_LEN)
        p->dsize = tmp_api.pay_len() - udp::UDP_HEADER_LEN;

    auto save_do_detect_content = do_detect_content;
    if ( p->dsize )
        do_detect_content = true;

#ifdef TICS_USE_RXP_MATCH
    tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

    fpEvalHeaderUdp(p, omd);

    p->ptrs.sp = tmp_sp;
    p->ptrs.dp = tmp_dp;
    p->ptrs.udph = tmp_udph;
    p->data = tmp_data;
    p->dsize = tmp_dsize;

    do_detect_content = save_do_detect_content;
}

/*
**
**  NAME
**    fpEvalPacket::
**
**  DESCRIPTION
**    This function is the interface to the snort_detect() routine.
**    the IP protocol is processed.  If it is TCP, UDP, or ICMP, we
**    process the both that particular ruleset and the IP ruleset
**    with in the fpEvalHeader for that protocol.  If the protocol
**    is not TCP, UDP, or ICMP, we just process the packet against
**    the IP rules at the end of the fpEvalPacket routine.  Since
**    we are using a setwise methodology for snort rules, both the
**    network layer rules and the transport layer rules are done
**    at the same time.  While this is not the best for modularity,
**    it is the best for performance, which is what we are working
**    on currently.
**
**  FORMAL INPUTS
**    Packet * - the packet to inspect
**
**  FORMAL OUTPUT
**    int - 0 means that packet has been processed.
**
*/
int fpEvalPacket(Packet* p)
{

    /* TICS modes check up */
#if defined (TICS_USE_RXP_MATCH) && !defined (TICS_GENERATE_RULE_FILE)
    fprintf(stdout, "Error: TICS RXP MATCH requires TICS_GENERATE_RULE_FILE");
    exit(-1);
#endif /* TICS_USE_RXP_MATCH && !TICS_GENERATE_RULE_FILE */

    OTNX_MATCH_DATA* omd = &t_omd;
    InitMatchInfo(omd);

    /* Run UDP rules against the UDP header of Teredo packets */
    // FIXIT-L udph is always inner; need to check for outer
    if ( p->ptrs.udph && (p->proto_bits & (PROTO_BIT__TEREDO | PROTO_BIT__GTP)) )
        fpEvalPacketUdp(p);

    switch (p->type())
    {
    case PktType::IP:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderIp(p, omd);
        fpEvalHeaderSvc(p, omd, SNORT_PROTO_IP);
        break;

    case PktType::ICMP:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderIcmp(p, omd);
        fpEvalHeaderSvc(p, omd, SNORT_PROTO_ICMP);
        break;

    case PktType::TCP:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderTcp(p, omd);
        fpEvalHeaderSvc(p, omd, SNORT_PROTO_TCP);
        break;

    case PktType::UDP:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderUdp(p, omd);
        fpEvalHeaderSvc(p, omd, SNORT_PROTO_UDP);
        break;

    case PktType::PDU:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        if ( snort_conf->sopgTable->user_mode )
            fpEvalHeaderSvc(p, omd, SNORT_PROTO_USER);

        // use ports if we don't know service or don't have rules
        else if ( p->proto_bits & PROTO_BIT__TCP )
        {
            if ( !p->get_application_protocol() or !fpEvalHeaderSvc(p, omd, SNORT_PROTO_TCP) )
                fpEvalHeaderTcp(p, omd);
        }
        else if ( p->proto_bits & PROTO_BIT__UDP )
        {
            if ( !p->get_application_protocol() or !fpEvalHeaderSvc(p, omd, SNORT_PROTO_UDP) )
                fpEvalHeaderUdp(p, omd);
        }
        break;

    case PktType::FILE:
#ifdef TICS_USE_RXP_MATCH
        /*TICS RXP analysis function call*/
        tics_scan_pkt(p);
#endif /* TICS_USE_RXP_MATCH */

        fpEvalHeaderSvc(p, omd, SNORT_PROTO_USER);
        break;

    default:
        break;
    }

    return fpFinalSelectEvent(omd, p);
}

OptTreeNode* GetOTN(uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn = OtnLookup(snort_conf->otn_map, gid, sid);

    if ( !otn )
        return nullptr;

    if ( !getRtnFromOtn(otn) )
    {
        // If not configured to autogenerate and there isn't an RTN, meaning
        // this rule isn't in the current policy, return nullptr.
        return nullptr;
    }

    return otn;
}

