/*
**
**  fpdetect.c
**
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**  Copyright (C) 2002-2013 Sourcefire, Inc.
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
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License Version 2 as
**  published by the Free Software Foundation.  You may not use, modify or
**  distribute this program under any other version of the GNU General
**  Public License.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
*/
#include "fpdetect.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort.h"
#include "detect.h"
#include "snort_debug.h"
#include "util.h"
#include "tag.h"
#include "rules.h"
#include "treenodes.h"
#include "pcrm.h"
#include "fpcreate.h"
#include "framework/cursor.h"
#include "framework/inspector.h"
#include "framework/ips_action.h"
#include "framework/mpse.h"
#include "bitop.h"
#include "perf_monitor/perf.h"
#include "perf_monitor/perf_event.h"
#include "filters/sfthreshold.h"
#include "filters/rate_filter.h"
#include "event_wrapper.h"
#include "packet_io/active.h"
#include "ips_options/ips_content.h"
#include "stream/stream_api.h"
#include "target_based/sftarget_protocol_reference.h"
#include "target_based/sftarget_reader.h"
#include "utils/sflsq.h"
#include "ppm.h"
#include "detection_util.h"
#include "detection_options.h"
#include "actions/actions.h"
#include "protocols/packet_manager.h"
#include "managers/action_manager.h"
#include "sfip/sf_ip.h"

#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"

/*
**  Static function prototypes
*/
int fpEvalRTN(RuleTreeNode *rtn, Packet *p, int check_ports);
static inline int fpEvalHeaderIp(Packet *p, int ip_proto, OTNX_MATCH_DATA *);
static inline int fpEvalHeaderIcmp(Packet *p, OTNX_MATCH_DATA *);
static inline int fpEvalHeaderTcp(Packet *p, OTNX_MATCH_DATA *);
static inline int fpEvalHeaderUdp(Packet *p, OTNX_MATCH_DATA *);
static inline int fpEvalHeaderSW(PORT_GROUP *port_group, Packet *p,
                                 int check_ports, char ip_rule, OTNX_MATCH_DATA *);
static int rule_tree_match (void* id, void * tree, int index, void * data, void *neg_list );
static inline int fpAddSessionAlert(Packet *p, OptTreeNode *otn);
static inline int fpSessionAlerted(Packet *p, OptTreeNode *otn);

#ifdef PERF_PROFILING
THREAD_LOCAL ProfileStats rulePerfStats;
THREAD_LOCAL ProfileStats ncrulePerfStats;
THREAD_LOCAL ProfileStats ruleRTNEvalPerfStats;
THREAD_LOCAL ProfileStats ruleOTNEvalPerfStats;
#endif

THREAD_LOCAL OTNX_MATCH_DATA t_omd;

/* initialize the global OTNX_MATCH_DATA variable */
void otnx_match_data_init(int num_rule_types)
{
    t_omd.iMatchInfoArraySize = num_rule_types;
    t_omd.matchInfo = (MATCH_INFO *)SnortAlloc(num_rule_types * sizeof(MATCH_INFO));
}

void otnx_match_data_term()
{
    if (t_omd.matchInfo != NULL)
        free(t_omd.matchInfo);

    t_omd.matchInfo = NULL;
}

/*
**
**  NAME
**    InitMatchInfo::
**
**  DESCRIPTION
**    Initialize the OTNX_MATCH_DATA structure.  We do this for
**    every packet so calloc is not used as this would zero the
**    whole space and this only sets the necessary counters to
**    zero, and saves us time.
**
**  FORMAL INPUTS
**    OTNX_MATCH_DATA * - pointer to structure to init.
**
**  FORMAL OUTPUT
**    None
**
*/
static inline void InitMatchInfo(OTNX_MATCH_DATA *o)
{
    int i = 0;

    for(i = 0; i < o->iMatchInfoArraySize; i++)
    {
        o->matchInfo[i].iMatchCount  = 0;
        o->matchInfo[i].iMatchIndex  = 0;
        o->matchInfo[i].iMatchMaxLen = 0;
    }
}

// called by fpLogEvent(), which does the filtering etc.
// this handles the non-rule-actions (responses).
static inline void fpLogOther (
    Packet* p, RuleTreeNode* rtn, OptTreeNode* otn, int action)
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
int fpLogEvent(RuleTreeNode *rtn, OptTreeNode *otn, Packet *p)
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
        ScAssureEstablished() &&
        (!(p->packet_flags & PKT_REBUILT_STREAM)) &&
        (otn->stateless == 0))
    {
        // We still want to drop packets that are drop rules.
        // We just don't want to see the alert.
        if ( block_action(rtn->type) )
            Active_DropSession();

        fpLogOther(p, rtn, otn, rtn->type);
        return 1;
    }

    // perform rate filtering tests - impacts action taken
    rateAction = RateFilter_Test(otn, p);
    override = ( rateAction >= RULE_TYPE__MAX );
    if ( override ) rateAction -= RULE_TYPE__MAX;

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
        if ( block_action(rtn->type) )
            Active_DropSession();

        pc.event_limit++;
        fpLogOther(p, rtn, otn, action);
        return 1;
    }

    /* If this packet has been passed based on detection rules,
     * check the decoder/preprocessor events (they have been added to Event queue already).
     * If its order is lower than 'pass', it should have been passed.
     * This is consistent with other detection rules */
	if ( (p->packet_flags & PKT_PASS_RULE)
         &&(ScGetEvalIndex(rtn->type) > ScGetEvalIndex(RULE_TYPE__PASS)))
	{
	    fpLogOther(p, rtn, otn, rtn->type);
	    return 1;
	}
    OTN_PROFILE_ALERT(otn);

    event_id++;
    action_execute(action, p, otn, event_id);
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
int fpAddMatch(OTNX_MATCH_DATA *omd_local, int pLen, OptTreeNode *otn)
{
    MATCH_INFO * pmi;
    int evalIndex;
    int i;
    RuleTreeNode *rtn = getRuntimeRtnFromOtn(otn);

    evalIndex = rtn->listhead->ruleListNode->evalIndex;

    /* bounds check index */
    if( evalIndex >= omd_local->iMatchInfoArraySize )
    {
        pc.match_limit++;
        return 1;
    }
    pmi = &omd_local->matchInfo[evalIndex];

    /*
    **  If we hit the max number of unique events for any rule type alert,
    **  log or pass, then we don't add it to the list.
    */
    if( pmi->iMatchCount >= (int)snort_conf->fast_pattern_config->max_queue_events ||
        pmi->iMatchCount >= MAX_EVENT_MATCH)
    {
        pc.match_limit++;
        return 1;
    }

    /* Check that we are not storing the same otn again */
    for( i=0; i< pmi->iMatchCount;i++ )
    {
        if( pmi->MatchArray[ i  ] == otn )
        {
            //LogMessage("fpAddMatch: storing the same otn...\n");
            return 0;
        }
    }

    /*
    **  Add the event to the appropriate list
    */
    pmi->MatchArray[ pmi->iMatchCount ] = otn;

    /*
    **  This means that we are adding a NC rule
    **  and we only set the index to this rule
    **  if there is no content rules in the
    **  same array.
    */
    if(pLen > 0)
    {
        /*
        **  Event Comparison Function
        **  Here the largest content match is the
        **  priority
        */
        if( pmi->iMatchMaxLen < pLen )
        {
            pmi->iMatchMaxLen = pLen;
            pmi->iMatchIndex  = pmi->iMatchCount;
        }
    }

    pmi->iMatchCount++;

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
int fpEvalRTN(RuleTreeNode *rtn, Packet *p, int check_ports)
{
    PROFILE_VARS;

    MODULE_PROFILE_START(ruleRTNEvalPerfStats);

    if(rtn == NULL)
    {
        MODULE_PROFILE_END(ruleRTNEvalPerfStats);
        return 0;
    }

    /* TODO: maybe add a port test here ... */

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "[*] Rule Head %d\n",
                rtn->head_node_number);)

    if(!rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func, check_ports))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                    "   => Header check failed, checking next node\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                    "   => returned from next node check\n"););
        MODULE_PROFILE_END(ruleRTNEvalPerfStats);
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
             "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT, "   => RTN %d Matched!\n",
                rtn->head_node_number););
    DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
            "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n"););
    /*
    **  Return that there is a rule match and log the event outside
    **  of this routine.
    */
    MODULE_PROFILE_END(ruleRTNEvalPerfStats);
    return 1;
}

static int detection_option_tree_evaluate(
    detection_option_tree_root_t *root,
    detection_option_eval_data_t *eval_data)
{
    int i, rval = 0;
    PROFILE_VARS;

    if (!root)
        return 0;

    MODULE_PROFILE_START(ruleOTNEvalPerfStats); /* Not really OTN, but close */

#ifdef PPM_MGR
    /* Start Rule Timer */
    if( PPM_RULES_ENABLED() )
    {
        PPM_GET_TIME();
        PPM_INIT_RULE_TIMER();
        dot_root_state_t* root_state = root->state + get_instance_id();

        if ( !root_state->enabled )
        {
            PPM_REENABLE_TREE(root, eval_data->p);

            if ( !root_state->enabled )
            {
                PPM_END_RULE_TIMER();
                return 0;
            }
        }
    }
#endif

    Cursor c(eval_data->p);

    for ( i = 0; i< root->num_children; i++)
    {
        /* Increment number of events generated from that child */
        rval += detection_option_node_evaluate(root->children[i], eval_data, c);
    }

#ifdef PPM_MGR
    if( PPM_ENABLED() )
    {
        PPM_GET_TIME();

        /* Rule test */
        if( PPM_RULES_ENABLED() )
        {
            if( PPM_PKTS_ENABLED() )
                PPM_INC_PKT_RULE_TESTS();

            PPM_RULE_TEST(root, eval_data->p);
            PPM_ACCUM_RULE_TIME();
            PPM_END_RULE_TIMER();
        }
    }
#endif

    MODULE_PROFILE_END(ruleOTNEvalPerfStats);
    return rval;
}

static int rule_tree_match( void * id, void *tree, int index, void * data, void * neg_list)
{
    OTNX_MATCH_DATA  *pomd   = (OTNX_MATCH_DATA *)data;
    PMX              *pmx    = (PMX*)id;
    PatternMatchData *pmd    = (PatternMatchData*)pmx->PatternMatchData;
    detection_option_tree_root_t *root = (detection_option_tree_root_t *)tree;
    detection_option_eval_data_t eval_data;
    NCListNode *ncl;
    int               rval=0;
    PROFILE_VARS;

    eval_data.pomd = pomd;
    eval_data.p = pomd->p;
    eval_data.pmd = pmd;
    eval_data.flowbit_failed = 0;
    eval_data.flowbit_noalert = 0;

    MODULE_PROFILE_START(rulePerfStats);

    /* NOTE: The otn will be the first one in the match state. If there are
     * multiple rules associated with a match state, mucking with the otn
     * may muck with an unintended rule */

    /* Set flag for not contents so they aren't evaluated */
    for (ncl = (NCListNode *)neg_list; ncl != NULL; ncl = ncl->next)
    {
        PMX *neg_pmx = (PMX *)ncl->pmx;
        PatternMatchData *neg_pmd = (PatternMatchData *)neg_pmx->PatternMatchData;

        assert(neg_pmd->last_check);

        PmdLastCheck* last_check =
            neg_pmd->last_check + get_instance_id();

        last_check->ts.tv_sec = eval_data.p->pkth->ts.tv_sec;
        last_check->ts.tv_usec = eval_data.p->pkth->ts.tv_usec;
        last_check->packet_number = (rule_eval_pkt_count
            + (PacketManager::get_rebuilt_packet_count()));
        last_check->rebuild_flag = (eval_data.p->packet_flags & PKT_REBUILT_STREAM);
    }

    rval = detection_option_tree_evaluate(root, &eval_data);
    if (rval)
    {
        /*
        **  We have a qualified event from this tree
        */
        pomd->pg->pgQEvents++;
        UpdateQEvents(&sfEvent);
    }
    else
    {
        /*
        ** This means that the event is non-qualified.
        */
        pomd->pg->pgNQEvents++;
        UpdateNQEvents(&sfEvent);
    }

    MODULE_PROFILE_END(rulePerfStats);
    if (eval_data.flowbit_failed)
    {
        return -1;
    }

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
            const uint8_t *tmp_data = eval_data.p->data;
            uint16_t tmp_dsize = eval_data.p->dsize;

            /* clear so we dont keep recursing */
            eval_data.p->packet_flags &= ~PKT_IP_RULE;
            eval_data.p->packet_flags |= PKT_IP_RULE_2ND;

            do
            {
                eval_data.p->data = eval_data.p->ptrs.ip_api.ip_data();
                eval_data.p->dsize = eval_data.p->ptrs.ip_api.pay_len();

                /* Recurse, and evaluate with the inner IP */
                rule_tree_match(id, tree, index, data, NULL);


            } while (layer::set_inner_ip_api(eval_data.p,
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

static int sortOrderByPriority(const void *e1, const void *e2)
{
    OptTreeNode *otn1;
    OptTreeNode *otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode **)e1;
    otn2 = *(OptTreeNode **)e2;

    if( otn1->sigInfo.priority < otn2->sigInfo.priority )
        return -1;

    if( otn1->sigInfo.priority > otn2->sigInfo.priority )
        return +1;

    /* This improves stability of repeated tests */
    if( otn1->sigInfo.id < otn2->sigInfo.id )
        return -1;

    if( otn1->sigInfo.id > otn2->sigInfo.id )
        return +1;

    return 0;
}

static int sortOrderByContentLength(const void *e1, const void *e2)
{
    OptTreeNode *otn1;
    OptTreeNode *otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode **)e1;
    otn2 = *(OptTreeNode **)e2;

    if (otn1->longestPatternLen < otn2->longestPatternLen)
        return +1;

    if (otn1->longestPatternLen > otn2->longestPatternLen)
        return -1;

    /* This improves stability of repeated tests */
    if( otn1->sigInfo.id < otn2->sigInfo.id )
        return +1;

    if( otn1->sigInfo.id > otn2->sigInfo.id )
        return -1;

    return 0;
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
static inline int fpFinalSelectEvent(OTNX_MATCH_DATA *o, Packet *p)
{
    int i;
    int j;
    int k;
    OptTreeNode *otn;
    int tcnt = 0;
    EventQueueConfig *eq = snort_conf->event_queue_config;
    RuleTreeNode *rtn;

    for( i = 0; i < o->iMatchInfoArraySize; i++ )
    {
        /* bail if were not dumping events in all the action groups,
         * and we've alresady got some events */
        if (!ScProcessAllEvents() && (tcnt > 0))
            return 1;

        if(o->matchInfo[i].iMatchCount)
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
                      sizeof(void *), sortOrderByPriority);
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
            for(j=0; j < o->matchInfo[i].iMatchCount; j++)
            {
                otn = o->matchInfo[i].MatchArray[j];
                rtn = getRtnFromOtn(otn);

                if ((otn != NULL) && (rtn != NULL) && pass_action(rtn->type))
                {
                    /* Already acted on rules, so just don't act on anymore */
                    if( tcnt > 0 )
                        return 1;
                }

                /*
                **  Loop here so we don't log the same event
                **  multiple times.
                */
                for(k = 0; k < j; k++)
                {
                    if(o->matchInfo[i].MatchArray[k] == otn)
                    {
                        otn = NULL;
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
                if ((otn != NULL) && (rtn != NULL) && pass_action(rtn->type))
                {
                    p->packet_flags |= PKT_PASS_RULE;
                    return 1;
                }
            }
        }
    }

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
// FIXIT-H this should include frags now that they are in session
static inline int fpAddSessionAlert(Packet *p, OptTreeNode *otn)
{
    if ( !p->flow )
        return 0;

    if ( !otn )
        return 0;

    return !stream.add_session_alert(
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
// FIXIT-H this should include frags now that they are in session
static inline int fpSessionAlerted(Packet *p, OptTreeNode *otn)
{
    SigInfo *si = &otn->sigInfo;

    if (!stream.check_session_alerted(p->flow, p, si->generator, si->id))
        return 0;
    else
        return 1;

}

#if 0
Not currently used
/*
 * Prints an OTN in a simple format with:
 *
 * rule proto: # gid: # sid: # sp: # dp # \n
 */
void printRuleFmt1( SnortConfig *sc, OptTreeNode * otn )
{
    RuleTreeNode *rtn = getParserRtnFromOtn(otn);

    LogMessage("rule proto: ");

    if(      rtn->proto== IPPROTO_TCP     )LogMessage("tcp  ");
    else if( rtn->proto== IPPROTO_UDP     )LogMessage("udp  ");
    else if( rtn->proto== IPPROTO_ICMP    )LogMessage("icmp ");
    else if( rtn->proto== ETHERNET_TYPE_IP)LogMessage("ip   ");

    LogMessage("gid:%u sid:%5u ", otn->sigInfo.generator,otn->sigInfo.id);

    LogMessage(" sp:");

    fflush(stdout);fflush(stderr);
    PortObjectPrintPortsRaw(rtn->src_portobject);
    fflush(stdout);fflush(stderr);

    LogMessage(" dp:");

    PortObjectPrintPortsRaw(rtn->dst_portobject);
    printf("\n");
    fflush(stdout);fflush(stderr);
}
#endif

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
**    PORT_GROUP * - the port group to inspect
**    Packet *     - the packet to inspect
**    int          - whether src/dst ports should be checked (udp/tcp or icmp)
**    char         - whether the rule is an IP rule (change the packet payload pointer)
**
**  FORMAL OUTPUTS
**    int - 0 for failed pattern match
**          1 for sucessful pattern match
**
*/
static inline int fpEvalHeaderSW(PORT_GROUP *port_group, Packet *p,
        int check_ports, char ip_rule, OTNX_MATCH_DATA *omd)
{
    Mpse* so;
    int start_state;
    const uint8_t *tmp_payload;
    ip::IpApi tmp_api;
    int8_t curr_ip_layer = 0;
    bool repeat = false;
    uint16_t tmp_dsize;
    FastPatternConfig *fp = snort_conf->fast_pattern_config;
    PROFILE_VARS;

    if (ip_rule)
    {
        // FIXIT-J -- Copying p->ip_data may be unnecessary because when
        //          finished evaluating, ip_api will be the innermost
        //          layer. Right now, ip_api should already be the
        //          innermost layer
        tmp_api = p->ptrs.ip_api;

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

    /*
     **  Init the info for rule ordering selection
     */
    //InitMatchInfo(omd);

    if (do_detect_content)
    {
        /*
         **  PKT_STREAM_INSERT packets are being rebuilt and re-injected
         **  through this detection engine.  So in order to avoid pattern
         **  matching bytes twice, we wait until the PKT_STREAM_INSERT
         **  packets are rebuilt and injected through the detection engine.
         **
         **  PROBLEM:
         **  If a stream gets stomped on before it gets re-injected, an attack
         **  would be missed.  So before a connection gets stomped, we
         **  re-inject the stream we have.
         */

        // FIXIT-M sdf etc. runs here

        if ( fp->inspect_stream_insert || !(p->packet_flags & PKT_STREAM_INSERT) )
        {
            Inspector* gadget = p->flow ? p->flow->gadget : nullptr;
            InspectionBuffer buf;

            omd->pg = port_group;
            omd->p = p;
            omd->check_ports = check_ports;

            if ( gadget )
            {
                if ( gadget->get_buf(InspectionBuffer::IBT_KEY, p, buf) )
                {
                    so = port_group->pgPms[PM_TYPE__HTTP_URI_CONTENT];

                    if ( so && so->get_pattern_count() > 0 )
                    {
                        start_state = 0;

                        so->search(buf.data, buf.len,
                            rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                        /* Bail if we spent too much time already */
                        if (PPM_PACKET_ABORT_FLAG())
                            goto fp_eval_header_sw_reset_ip;
#endif
                    }
                }
                if ( gadget->get_buf(InspectionBuffer::IBT_HEADER, p, buf) )
                {
                    so = port_group->pgPms[PM_TYPE__HTTP_HEADER_CONTENT];

                    if ( so && so->get_pattern_count() > 0 )
                    {
                        start_state = 0;

                        so->search(buf.data, buf.len,
                            rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                        /* Bail if we spent too much time already */
                        if (PPM_PACKET_ABORT_FLAG())
                            goto fp_eval_header_sw_reset_ip;
#endif
                    }
                }
                if ( gadget->get_buf(InspectionBuffer::IBT_BODY, p, buf) )
                {
                    so = port_group->pgPms[PM_TYPE__HTTP_CLIENT_BODY_CONTENT];

                    if ( so && so->get_pattern_count() > 0 )
                    {
                        start_state = 0;

                        so->search(buf.data, buf.len,
                            rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                        /* Bail if we spent too much time already */
                        if (PPM_PACKET_ABORT_FLAG())
                            goto fp_eval_header_sw_reset_ip;
#endif
                    }
                }
            }
            /*
             **  Decode Content Match
             **  We check to see if the packet has been normalized into
             **  the global (decode.c) DecodeBuffer.  Currently, only
             **  telnet normalization writes to this buffer.  So, if
             **  it is set, we do this the match against the normalized
             **  buffer and we do the check against the original
             **  payload, in case any of the rules have the
             **  'rawbytes' option.
             */
            // FIXIT-H alt buf and file data should be obtained from 
            // inspector gadget as an extension of above
            so = port_group->pgPms[PM_TYPE__CONTENT];

            if ( so && so->get_pattern_count() > 0 )
            {
                if(g_alt_data.len)
                {
                    start_state = 0;
                    so->search(g_alt_data.data, g_alt_data.len,
                        rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                    /* Bail if we spent too much time already */
                    if (PPM_PACKET_ABORT_FLAG())
                        goto fp_eval_header_sw_reset_ip;
#endif
                }

                if(g_file_data.len)
                {
                    start_state = 0;
                    so->search(g_file_data.data, g_file_data.len,
                        rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                    /* Bail if we spent too much time already */
                    if (PPM_PACKET_ABORT_FLAG())
                        goto fp_eval_header_sw_reset_ip;
#endif
                }

                 /*
                 **  Content-Match - If no Uri-Content matches, than do a Content search
                 **
                 **  NOTE:
                 **    We may want to bail after the Content search if there
                 **    has been a successful match.
                 */
                if (p->data && p->dsize)
                {
                    uint16_t pattern_match_size = p->dsize;

                    if ( IsLimitedDetect(p) && (p->alt_dsize < p->dsize) )
                        pattern_match_size = p->alt_dsize;

                    start_state = 0;
                    so->search(p->data, pattern_match_size,
                            rule_tree_match, omd, &start_state);
#ifdef PPM_MGR
                    /* Bail if we spent too much time already */
                    if (PPM_PACKET_ABORT_FLAG())
                        goto fp_eval_header_sw_reset_ip;
#endif
                }
            }
        }
    }

    /*
     **  PKT_REBUILT_STREAM packets are re-injected streams.  This means
     **  that the "packet headers" are completely bogus and only the
     **  content matches are important.  So for PKT_REBUILT_STREAMs, we
     **  don't inspect against no-content OTNs since these deal with
     **  packet headers, packet sizes, etc.
     **
     **  NOTE:
     **  This has been changed when evaluating no-content rules because
     **  it was interfering with the pass->alert ordering.  We still
     **  need to check no-contents against rebuilt packets, because of
     **  this problem.  Immediate solution is to have the detection plugins
     **  bail if the rule should only be inspected against packets, a.k.a
     **  dsize checks.
     **
     **  NOTE 2:
     **  PKT_REBUILT_STREAM packets are now cooked (encoded by Snort)
     **  and have the same encapsulations as the raw packets.  The
     **  headers are "good enough" for detection (valid TCP sequence
     **  numbers, but zero checksums) but packet sizes are different.
     **  Given that TCP segmentation is arbitrary to start with, the
     **  use of dsize in a rule is questionable for raw or rebuilt.
     */

    /*
     **  Walk and test the non-content OTNs
     */
    if (fpDetectGetDebugPrintNcRules(fp))
        LogMessage("NC-testing %u rules\n", port_group->pgNoContentCount);

#ifdef PPM_MGR
    if( PPM_ENABLED() )
        PPM_GET_TIME();
#endif

    do
    {
        if (port_group->pgHeadNC)
        {
            detection_option_eval_data_t eval_data;
            int rval;

            eval_data.pomd = omd;
            eval_data.p = p;
            eval_data.pmd = NULL;
            eval_data.flowbit_failed = 0;
            eval_data.flowbit_noalert = 0;

            MODULE_PROFILE_START(ncrulePerfStats);
            rval = detection_option_tree_evaluate((detection_option_tree_root_t*)port_group->pgNonContentTree, &eval_data);
            MODULE_PROFILE_END(ncrulePerfStats);

            if (rval)
            {
                /* We have a qualified event from this tree */
                port_group->pgQEvents++;
                UpdateQEvents(&sfEvent);
            }
            else
            {
                /* This means that the event is non-qualified. */
                port_group->pgNQEvents++;
                UpdateNQEvents(&sfEvent);
            }
        }

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
    while(repeat);

#ifdef PPM_MGR  /* Tag only used with PPM right now */
fp_eval_header_sw_reset_ip:
#endif

    return 0;
}

/*
** fpEvalHeaderUdp::
*/
static inline int fpEvalHeaderUdp(Packet *p, OTNX_MATCH_DATA *omd)
{
    PORT_GROUP *src = NULL, *dst = NULL, *gen = NULL;

    if (IsAdaptiveConfigured())
    {
        /* Check for a service/protocol ordinal for this packet */
        int16_t proto_ordinal = GetProtocolReference(p);

        DEBUG_WRAP( DebugMessage(DEBUG_ATTRIBUTE,"proto_ordinal=%d\n",proto_ordinal););

        if (proto_ordinal > 0)
        {
            /* Grab the generic group -- the any-any rules */
            prmFindGenericRuleGroup(snort_conf->prmTcpRTNX, &gen);

            /* TODO:  To From Server ?, else we apply  */
            dst = fpGetServicePortGroupByOrdinal(snort_conf->sopgTable, IPPROTO_UDP,
                                                 TO_SERVER, proto_ordinal);
            src = fpGetServicePortGroupByOrdinal(snort_conf->sopgTable, IPPROTO_UDP,
                                                 TO_CLIENT, proto_ordinal);

            DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE,
                        "fpEvalHeaderUdpp:targetbased-ordinal-lookup: "
                        "sport=%d, dport=%d, proto_ordinal=%d, src:%x, "
                        "dst:%x, gen:%x\n",p->ptrs.sp,p->ptrs.dp,proto_ordinal,src,dst,gen););
        }
    }

    if ((src == NULL) && (dst == NULL))
    {
        /* we did not have a target based port group, use ports */
        if (!prmFindRuleGroupUdp(snort_conf->prmUdpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &gen))
            return 0;

        DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE,
                    "fpEvalHeaderUdp: sport=%d, dport=%d, "
                    "src:%x, dst:%x, gen:%x\n",p->ptrs.sp,p->ptrs.dp,src,dst,gen););
    }

    if (fpDetectGetDebugPrintNcRules(snort_conf->fast_pattern_config))
    {
        LogMessage(
            "fpEvalHeaderUdp: sport=%d, dport=%d, src:%p, dst:%p, gen:%p\n",
             p->ptrs.sp, p->ptrs.dp, (void*)src, (void*)dst, (void*)gen);
    }

    InitMatchInfo(omd);

    if (dst != NULL)
    {
        if (fpEvalHeaderSW(dst, p, 1, 0, omd))
            return 1;
    }

    if (src != NULL)
    {
        if (fpEvalHeaderSW(src, p, 1, 0, omd))
            return 1;
    }

    if (gen != NULL)
    {
        if (fpEvalHeaderSW(gen, p, 1, 0, omd))
            return 1;
    }

    return fpFinalSelectEvent(omd, p);
}

/*
**  fpEvalHeaderTcp::
*/
static inline int fpEvalHeaderTcp(Packet *p, OTNX_MATCH_DATA *omd)
{
    PORT_GROUP *src = NULL, *dst = NULL, *gen = NULL;

    if (IsAdaptiveConfigured())
    {
        int16_t proto_ordinal = GetProtocolReference(p);

        DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "proto_ordinal=%d\n", proto_ordinal););

        if (proto_ordinal > 0)
        {
            /* Grab the generic group -- the any-any rules */
            prmFindGenericRuleGroup(snort_conf->prmTcpRTNX, &gen);

            if (p->packet_flags & PKT_FROM_SERVER) /* to cli */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_server\n"););

                src = fpGetServicePortGroupByOrdinal(snort_conf->sopgTable, IPPROTO_TCP,
                                                     0 /*to_cli */,  proto_ordinal);
            }

            if (p->packet_flags & PKT_FROM_CLIENT) /* to srv */
            {
                DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "pkt_from_client\n"););

                dst = fpGetServicePortGroupByOrdinal(snort_conf->sopgTable, IPPROTO_TCP,
                                                     1 /*to_srv */,  proto_ordinal);
            }

            DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE,
                        "fpEvalHeaderTcp:targetbased-ordinal-lookup: "
                        "sport=%d, dport=%d, proto_ordinal=%d, src:%x, "
                        "dst:%x, gen:%x\n",p->ptrs.sp,p->ptrs.dp,proto_ordinal,src,dst,gen););
        }
    }

    if ((src == NULL) && (dst == NULL))
    {
        /* grab the src/dst groups from the lookup above */
        if (!prmFindRuleGroupTcp(snort_conf->prmTcpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &gen))
            return 0;

        DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE,
                    "fpEvalHeaderTcp: sport=%d, "
                    "dport=%d, src:%x, dst:%x, gen:%x\n",p->ptrs.sp,p->ptrs.dp,src,dst,gen););
    }

    if (fpDetectGetDebugPrintNcRules(snort_conf->fast_pattern_config))
    {
        LogMessage(
            "fpEvalHeaderTcp: sport=%d, dport=%d, src:%p, dst:%p, gen:%p\n",
             p->ptrs.sp, p->ptrs.dp, (void*)src, (void*)dst, (void*)gen);
    }

    InitMatchInfo(omd);

    if (dst != NULL)
    {
        if (fpEvalHeaderSW(dst, p, 1, 0, omd))
            return 1;
    }

    if (src != NULL)
    {
        if (fpEvalHeaderSW(src, p, 1, 0, omd))
            return 1;
    }

    if (gen != NULL)
    {
        if(fpEvalHeaderSW(gen, p, 1, 0, omd))
            return 1;
    }

    return fpFinalSelectEvent(omd, p);
}

/*
**  fpEvalHeaderICMP::
*/
static inline int fpEvalHeaderIcmp(Packet *p, OTNX_MATCH_DATA *omd)
{
    PORT_GROUP *gen = NULL, *type = NULL;

    if (!prmFindRuleGroupIcmp(snort_conf->prmIcmpRTNX, p->ptrs.icmph->type, &type, &gen))
        return 0;

    if (fpDetectGetDebugPrintNcRules(snort_conf->fast_pattern_config))
    {
        LogMessage(
            "fpEvalHeaderIcmp: icmp->type=%d type=%p gen=%p\n",
            p->ptrs.icmph->type, (void*)type, (void*)gen);
    }

    InitMatchInfo(omd);

    if (type != NULL)
    {
        if (fpEvalHeaderSW(type, p, 0, 0, omd))
            return 1;
    }

    if (gen != NULL)
    {
        if (fpEvalHeaderSW(gen, p, 0, 0, omd))
            return 1;
    }

    return fpFinalSelectEvent(omd, p);
}

/*
**  fpEvalHeaderIP::
*/
static inline int fpEvalHeaderIp(Packet *p, int ip_proto, OTNX_MATCH_DATA *omd)
{
    PORT_GROUP *gen = NULL, *ip_group = NULL;

    if (!prmFindRuleGroupIp(snort_conf->prmIpRTNX, ip_proto, &ip_group, &gen))
        return 0;

    if(fpDetectGetDebugPrintNcRules(snort_conf->fast_pattern_config))
        LogMessage("fpEvalHeaderIp: ip_group=%p, gen=%p\n", (void*)ip_group, (void*)gen);

    InitMatchInfo(omd);

    if (ip_group != NULL)
    {
        if (fpEvalHeaderSW(ip_group, p, 0, 1, omd))
            return 1;
    }

    if (gen != NULL)
    {
        if (fpEvalHeaderSW(gen, p, 0, 1, omd))
            return 1;
    }

    return fpFinalSelectEvent(omd, p);
}

/*
**
**  NAME
**    fpEvalPacket::
**
**  DESCRIPTION
**    This function is the interface to the Detect() routine.  Here
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
int fpEvalPacket(Packet *p)
{
    OTNX_MATCH_DATA *omd = &t_omd;

    /* Run UDP rules against the UDP header of Teredo packets */
    if ( p->ptrs.udph && (p->proto_bits & (PROTO_BIT__TEREDO | PROTO_BIT__GTP)) )
    {
        uint16_t tmp_sp = p->ptrs.sp;
        uint16_t tmp_dp = p->ptrs.dp;
        const udp::UDPHdr *tmp_udph = p->ptrs.udph;
        const uint8_t *tmp_data = p->data;
        int tmp_do_detect_content = do_detect_content;
        uint16_t tmp_dsize = p->dsize;

        const udp::UDPHdr* udph = layer::get_outer_udp_lyr(p);

        p->ptrs.udph = udph;
        p->ptrs.sp = ntohs(udph->uh_sport);
        p->ptrs.dp = ntohs(udph->uh_dport);
        p->data = (const uint8_t *)udph + udp::UDP_HEADER_LEN;

        ip::IpApi tmp_api;
        int8_t curr_layer = 0;
        layer::set_outer_ip_api(p, tmp_api, curr_layer);

        if (tmp_api.pay_len() >  udp::UDP_HEADER_LEN)
            p->dsize = tmp_api.pay_len() - udp::UDP_HEADER_LEN;

        if (p->dsize)
            do_detect_content = 1;

        fpEvalHeaderUdp(p, omd);

        p->ptrs.sp = tmp_sp;
        p->ptrs.dp = tmp_dp;
        p->ptrs.udph = tmp_udph;
        p->data = tmp_data;
        p->dsize = tmp_dsize;
        do_detect_content = tmp_do_detect_content;
    }

    switch(p->type())
    {
    case PktType::TCP:
        return fpEvalHeaderTcp(p, omd);

    case PktType::UDP:
        return fpEvalHeaderUdp(p, omd);

    case PktType::ICMP:
        DEBUG_WRAP(DebugMessage(DEBUG_DETECT,
                    "Detecting on IcmpList\n"););
        return fpEvalHeaderIcmp(p, omd);

    /*
    **  No Match on TCP/UDP, Do IP
    */
    default:
        return fpEvalHeaderIp(p, -1, omd);
        break;
    }

}

// FIXIT-M delete this - see fpAddIpProtoOnlyRule() for details
void fpEvalIpProtoOnlyRules(Packet *p, uint8_t proto_id)
{
    if ((p != NULL) && p->has_ip())
    {
        SF_LIST *l = snort_conf->ip_proto_only_lists[proto_id];
        OptTreeNode *otn;
        SF_LNODE* cursor;

        /* If list is NULL, sflist_first returns NULL */
        for (otn = (OptTreeNode *)sflist_first(l, &cursor);
             otn != NULL;
             otn = (OptTreeNode *)sflist_next(&cursor))
        {
            if (fpEvalRTN(getRuntimeRtnFromOtn(otn), p, 0))
            {
                if ( SnortEventqAdd(otn) )
                    pc.queue_limit++;

                if ( pass_action(getRuntimeRtnFromOtn(otn)->type) )
                    p->packet_flags |= PKT_PASS_RULE;
            }
        }
    }
}


OptTreeNode * GetOTN(uint32_t gid, uint32_t sid)
{
    OptTreeNode *otn = OtnLookup(snort_conf->otn_map, gid, sid);

    if ( !otn )
        return nullptr;

    if ( !getRtnFromOtn(otn) )
    {
        // If not configured to autogenerate and there isn't an RTN, meaning
        // this rule isn't in the current policy, return NULL.
        return nullptr;
    }

    return otn;
}

