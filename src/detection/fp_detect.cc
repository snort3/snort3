//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fp_detect.h"

#include "events/event.h"
#include "filters/rate_filter.h"
#include "filters/sfthreshold.h"
#include "framework/cursor.h"
#include "framework/mpse.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "managers/action_manager.h"
#include "packet_io/active.h"
#include "packet_tracer/packet_tracer.h"
#include "parser/parser.h"
#include "profiler/profiler_defs.h"
#include "protocols/icmp4.h"
#include "protocols/packet_manager.h"
#include "protocols/udp.h"
#include "search_engines/pat_stats.h"
#include "stream/stream.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "context_switcher.h"
#include "detect.h"
#include "detect_trace.h"
#include "detection_util.h"
#include "detection_engine.h"
#include "detection_module.h"
#include "detection_options.h"
#include "fp_config.h"
#include "fp_create.h"
#include "ips_context.h"
#include "pattern_match_data.h"
#include "pcrm.h"
#include "rules.h"
#include "service_map.h"
#include "tag.h"
#include "treenodes.h"

using namespace snort;

enum FPTask : uint8_t
{
    FP = 1,
    NON_FP = 2
};

THREAD_LOCAL ProfileStats mpsePerfStats;
THREAD_LOCAL ProfileStats rulePerfStats;

static void fp_immediate(Packet*);
static void fp_immediate(MpseGroup*, Packet*, const uint8_t*, unsigned);

static inline void init_match_info(const IpsContext* c)
{
    for ( unsigned i = 0; i < c->conf->num_rule_types; i++ )
        c->otnx->matchInfo[i].iMatchCount = 0;

    c->otnx->have_match = false;
}

// called by fpLogEvent(), which does the filtering etc.
// this handles the non-rule-actions (responses).
static inline void fpLogOther(
    Packet* p, const RuleTreeNode* rtn, const OptTreeNode* otn, int action)
{
    if ( EventTrace_IsEnabled(p->context->conf) )
        EventTrace_Log(p, otn, action);

    if ( PacketTracer::is_active() )
    {
        PacketTracer::log("Event: %u:%u:%u, Action %s\n",
            otn->sigInfo.gid, otn->sigInfo.sid,
            otn->sigInfo.rev, Actions::get_string((Actions::Type)action));
    }

    // rule option actions are queued here (eg replace)
    otn_trigger_actions(otn, p);

    // rule actions are queued here (eg reject)
    if ( rtn->listhead->is_plugin_action )
    {
        Actions::Type idx = rtn->listhead->ruleListNode->mode;
        ActiveAction * act = get_ips_policy()->action[idx];
        if ( act )
            Active::queue(act, p);
    }
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

    if ( Actions::is_pass(rtn->action) )
        p->packet_flags |= PKT_PASS_RULE;

    if ( otn->stateless() )
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
        p->context->conf->assure_established() &&
        (!(p->packet_flags & PKT_REBUILT_STREAM)) &&
        !otn->stateless() )
    {
        // We still want to drop packets that are drop rules.
        // We just don't want to see the alert.
        Actions::apply(rtn->action, p);
        fpLogOther(p, rtn, otn, rtn->action);
        return 1;
    }

    // perform rate filtering tests - impacts action taken
    rateAction = RateFilter_Test(otn, p);
    override = ( rateAction >= Actions::MAX );
    if ( override )
        rateAction -= Actions::MAX;

    // internal events are no-ops
    if ( (rateAction < 0) && EventIsInternal(otn->sigInfo.gid) )
    {
        return 1;
    }
    action = (rateAction < 0) ? (int)rtn->action : rateAction;

    // When rate filters kick in, event filters are still processed.
    // perform event filtering tests - impacts logging
    if ( p->ptrs.ip_api.is_valid() )
    {
        filterEvent = sfthreshold_test(
            otn->sigInfo.gid, otn->sigInfo.sid,
            p->ptrs.ip_api.get_src(), p->ptrs.ip_api.get_dst(),
            p->pkth->ts.tv_sec, get_network_policy()->policy_id);
    }
    else
    {
        SfIp cleared;
        cleared.clear();

        filterEvent = sfthreshold_test(
            otn->sigInfo.gid, otn->sigInfo.sid,
            &cleared, &cleared, p->pkth->ts.tv_sec, get_network_policy()->policy_id);
    }

    if ( (filterEvent < 0) || (filterEvent > 0 && !override) )
    {
        /*
        **  If InlineMode is on, then we still want to drop packets
        **  that are drop rules.  We just don't want to see the alert.
        */
        Actions::apply((Actions::Type)action, p);
        fpLogOther(p, rtn, otn, action);
        pc.event_limit++;
        return 1;
    }

    /* If this packet has been passed based on detection rules,
     * check the decoder/preprocessor events (they have been added to Event queue already).
     * If its order is lower than 'pass', it should have been passed.
     * This is consistent with other detection rules */
    const SnortConfig* sc = p->context->conf;

    if ( (p->packet_flags & PKT_PASS_RULE) &&
        (sc->get_eval_index(rtn->action) > sc->get_eval_index(Actions::PASS)) )
    {
        fpLogOther(p, rtn, otn, rtn->action);
        return 1;
    }

    otn->state[get_instance_id()].alerts++;

    event_id++;
    Actions::execute((Actions::Type)action, p, otn, event_id);
    fpLogOther(p, rtn, otn, action);

    return 0;
}

/*
**  DESCRIPTION
**    Add an Event to the appropriate Match Queue: Alert, Pass, or Log.
**    This allows us to find multiple events per packet and pick the 'best'
**    one.  This function also allows us to change the order of alert,
**    pass, and log signatures by caching them for decision later.
**
**  IMPORTANT NOTE:
**    fpAddMatch must be called even when the queue has been maxed
**    out.  This is because there are three different queues (alert,
**    pass, log) and unless all three are filled (or at least the
**    queue that is in the highest priority), events must be looked
**    at to see if they are members of a queue that is not maxed out.
**
**  FORMAL INPUTS
**    OtnxMatchData    * - the omd to add the event to.
**    OptTreeNode        * - the otn to add.
**
**  FORMAL OUTPUTS
**    int - 1 max_events variable hit, 0 successful.
**
*/
int fpAddMatch(OtnxMatchData* omd, const OptTreeNode* otn)
{
    RuleTreeNode* rtn = getRuntimeRtnFromOtn(otn);
    unsigned evalIndex = rtn->listhead->ruleListNode->evalIndex;

    const SnortConfig* sc = SnortConfig::get_conf();

    /* bounds check index */
    if ( evalIndex >= sc->num_rule_types )
    {
        pc.match_limit++;
        return 1;
    }
    MatchInfo* pmi = &omd->matchInfo[evalIndex];

    /*
    **  If we hit the max number of unique events for any rule type alert,
    **  log or pass, then we don't add it to the list.
    */
    if ( pmi->iMatchCount >= sc->fast_pattern_config->get_max_queue_events() ||
        pmi->iMatchCount >= MAX_EVENT_MATCH)
    {
        pc.match_limit++;
        return 1;
    }

    // don't store the same otn again
    for ( unsigned i = 0; i < pmi->iMatchCount; i++ )
    {
        if ( pmi->MatchArray[i] == otn )
            return 0;
    }

    //  add the event to the appropriate list
    pmi->MatchArray[ pmi->iMatchCount ] = otn;
    pmi->iMatchCount++;
    omd->have_match = true;
    return 0;
}

bool fp_eval_rtn(RuleTreeNode* rtn, Packet* p, int check_ports)
{
    if ( !rtn or !rtn->enabled() )
        return false;

    if ( rtn->user_mode() )
        check_ports = 1;

    if (!rtn->rule_func->RuleHeadFunc(p, rtn, rtn->rule_func, check_ports))
        return false;

    return true;
}

int fp_eval_option(void* v, Cursor& c, Packet* p)
{
    IpsOption* opt = (IpsOption*)v;
    return opt->eval(c, p);
}

static int detection_option_tree_evaluate(detection_option_tree_root_t* root,
    detection_option_eval_data_t& eval_data)
{
    if ( !root )
        return 0;

    RuleLatency::Context rule_latency_ctx(root, eval_data.p);

    if ( RuleLatency::suspended() )
        return 0;

    Cursor c(eval_data.p);
    int rval = 0;

    debug_log(detection_trace, TRACE_RULE_EVAL, nullptr, "Starting tree eval\n");

    for ( int i = 0; i < root->num_children; ++i )
    {
        // Increment number of events generated from that child
        rval += detection_option_node_evaluate(root->children[i], eval_data, c);
    }
    clear_trace_cursor_info();

    return rval;
}

static int rule_tree_match(
    void* user, void* tree, int index, void* context, void* neg_list)
{
    PMX* pmx = (PMX*)user;

    detection_option_tree_root_t* root = (detection_option_tree_root_t*)tree;
    detection_option_eval_data_t eval_data;
    NCListNode* ncl;

    eval_data.p = ((IpsContext*)context)->packet;
    eval_data.pmd = pmx->pmd;
    eval_data.flowbit_failed = 0;
    eval_data.flowbit_noalert = 0;

    print_pattern(pmx->pmd, eval_data.p);

    {
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
            last_check->run_num = get_run_num();
            last_check->context_num = eval_data.p->context->context_num;
            last_check->rebuild_flag = (eval_data.p->packet_flags & PKT_REBUILT_STREAM);
        }

        int ret = detection_option_tree_evaluate(root, eval_data);

        if ( ret )
            pmqs.qualified_events++;
        else
            pmqs.non_qualified_events++;
    }

    if (eval_data.flowbit_failed)
        return -1;

    /* If this is for an IP rule set, evaluate the rules from
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

            /* clear so we don't keep recursing */
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
                eval_data.p->ptrs.ip_api, curr_layer) && (eval_data.p->ptrs.ip_api != tmp_api));

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
    const OptTreeNode* otn1;
    const OptTreeNode* otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode* const*)e1;
    otn2 = *(OptTreeNode* const*)e2;

    if ( otn1->sigInfo.priority < otn2->sigInfo.priority )
        return -1;

    if ( otn1->sigInfo.priority > otn2->sigInfo.priority )
        return +1;

    /* This improves stability of repeated tests */
    if ( otn1->sigInfo.sid < otn2->sigInfo.sid )
        return -1;

    if ( otn1->sigInfo.sid > otn2->sigInfo.sid )
        return +1;

    return 0;
}

// FIXIT-L pattern length is not a valid event sort criterion for
// non-literals
static int sortOrderByContentLength(const void* e1, const void* e2)
{
    const OptTreeNode* otn1;
    const OptTreeNode* otn2;

    if (!e1 || !e2)
        return 0;

    otn1 = *(OptTreeNode* const*)e1;
    otn2 = *(OptTreeNode* const*)e2;

    if (otn1->longestPatternLen < otn2->longestPatternLen)
        return +1;

    if (otn1->longestPatternLen > otn2->longestPatternLen)
        return -1;

    /* This improves stability of repeated tests */
    if ( otn1->sigInfo.sid < otn2->sigInfo.sid )
        return +1;

    if ( otn1->sigInfo.sid > otn2->sigInfo.sid )
        return -1;

    return 0;
}

/*
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
*/
static inline int fpAddSessionAlert(Packet* p, const OptTreeNode* otn)
{
    if ( !p->flow )
        return 0;

    if ( !otn )
        return 0;

    return !Stream::add_flow_alert(p->flow, p, otn->sigInfo.gid, otn->sigInfo.sid);
}

/*
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
*/
static inline int fpSessionAlerted(Packet* p, const OptTreeNode* otn)
{
    const SigInfo* si = &otn->sigInfo;

    if (!Stream::check_flow_alerted(p->flow, p, si->gid, si->sid))
        return 0;
    else
        return 1;
}

/*
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
**  IMPORTANT NOTE:
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
**  MORE NOTES
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
**    on the packet, but the packet does not pass.  Also, the --treat-drop-as-alert
**    flag causes any drop/block/reset rules to be loaded as alert rules.
**    The default has been to ignore them on parsing.
**
**    If this is less than clear, here's the $.02 version:
**    default order -> pass drop alert log ( --alert-before-pass reverts
**    to -> drop alert pass log ) the 1st action-type of events in the rule
**    ordering to be seen gets logged by default the --flush-all-events
**    flag will cause secondary and tertiary action-events to be logged.
**    the -o flag is useless, but accepted, for now.
**    the max_events and log fields are reduced to only needing the log
**    events field. max_fields is harmless.
**    ( drop rules may be honored as alerts in IDS mode (no -Q) by using
**    the --treat-drop-as-alert)
**
**  FORMAL INPUTS
**    OtnxMatchData * - omd to select event from.
**    Packet *          - pointer to packet to log.
**
**  FORMAL OUTPUT
**    int - return 0 if no match, 1 if match.
*/
static inline int fpFinalSelectEvent(OtnxMatchData* omd, Packet* p)
{
    if ( !omd->have_match )
        return 0;

    unsigned tcnt = 0;
    EventQueueConfig* eq = p->context->conf->event_queue_config;
    int (*compar)(const void *, const void *);
    compar = ( eq->order == SNORT_EVENTQ_PRIORITY )
        ? &sortOrderByPriority : sortOrderByContentLength;

    for ( unsigned i = 0; i < p->context->conf->num_rule_types; i++ )
    {
        /* bail if were not dumping events in all the action groups,
         * and we've already got some events */
        if (!p->context->conf->process_all_events() && (tcnt > 0))
            return 1;

        if ( omd->matchInfo[i].iMatchCount )
        {
            /*
             * We must always sort so if we que 8 and log 3 and they are
             * all from the same action group we want them sorted so we get
             * the highest 3 in priority, priority and length sort do NOT
             * take precedence over 'alert drop pass ...' ordering.  If
             * order is 'drop alert', and we log 3 for drop alerts do not
             * get logged.  IF order is 'alert drop', and we log 3 for
             * alert, then no drops are logged.  So, there should be a
             * built in drop/block/reset comes before alert/pass/log as
             * part of the natural ordering....Jan '06..
             */
            /* Sort the rules in this action group */
            qsort(omd->matchInfo[i].MatchArray, omd->matchInfo[i].iMatchCount,
                sizeof(void*), compar);

            /* Process each event in the action (alert,drop,log,...) groups */
            for (unsigned j = 0; j < omd->matchInfo[i].iMatchCount; j++)
            {
                const OptTreeNode* otn = omd->matchInfo[i].MatchArray[j];
                RuleTreeNode* rtn = getRtnFromOtn(otn);

                if ( otn && rtn && Actions::is_pass(rtn->action) )
                {
                    /* Already acted on rules, so just don't act on anymore */
                    if ( tcnt > 0 )
                        return 1;
                }

                //  Loop here so we don't log the same event multiple times.
                for (unsigned k = 0; k < j; k++)
                {
                    if ( omd->matchInfo[i].MatchArray[k] == otn )
                    {
                        otn = nullptr;
                        break;
                    }
                }

                if ( otn && !fpSessionAlerted(p, otn) )
                {
                    if ( DetectionEngine::queue_event(otn) )
                        pc.queue_limit++;

                    tcnt++;
                }
                else
                    pc.alert_limit++;

                /* Only count it if we're going to log it */
                if ( tcnt <= eq->log_events )
                {
                    if ( p->flow )
                        fpAddSessionAlert(p, otn);
                }

                if ( tcnt >= eq->max_events )
                {
                    pc.queue_limit++;
                    return 1;
                }

                /* only log/count one pass */
                if ( otn && rtn && Actions::is_pass(rtn->action) )
                {
                    p->packet_flags |= PKT_PASS_RULE;
                    return 1;
                }
            }
        }
    }

    return 0;
}

struct Node
{
    void* user;
    void* tree;
    void* list;
    int index;
};


class MpseStash
{
public:
    MpseStash(unsigned limit)
        : max(limit)
    { }

    void init()
    {
        if ( enable )
            count = 0;
    }

    // this is done in the offload thread
    bool push(void* user, void* tree, int index, void* list);

    // this is done in the packet thread
    bool process(MpseMatch, void*);

    void disable_process()
    { enable = false; }

    void enable_process()
    { enable = true; }

private:
    bool enable = false;
    unsigned count = 0;
    unsigned max;
    std::vector<Node> queue;

    // perf trade-off, same as Snort 2
    // queue to keep mpse search cache warm
    // but limit to avoid the O(n**2) effect of inserts
    // and to get any rule hits before exhaustive searching
    // consider a map in lieu of vector
    const unsigned queue_limit = 32;
};

// uniquely insert into q, should splay elements for performance
// return true if maxed out to trigger a flush
bool MpseStash::push(void* user, void* tree, int index, void* list)
{

    for ( auto it = queue.rbegin(); it != queue.rend(); it++ )
    {
        if ( tree == (*it).tree )
        {
            pmqs.tot_inq_inserts++;
            return false;
        }
    }

    if ( max and ( count == max ) )
    {
        pmqs.tot_inq_overruns++;
        return false;
    }

    Node node;
    node.user = user;
    node.tree = tree;
    node.index = index;
    node.list = list;
    queue.push_back(node);
    pmqs.tot_inq_uinserts++;
    pmqs.tot_inq_inserts++;
    count++;

    if ( queue.size() == queue_limit )
        return true;  // process now

    return false;
}

bool MpseStash::process(MpseMatch match, void* context)
{
    if ( !enable )
        return true;  // maxed out - quit, FIXIT-RC count this condition

    if ( count > pmqs.max_inq )
        pmqs.max_inq = count;


#ifdef DEBUG_MSGS
    if (count == 0)
        debug_log(detection_trace, TRACE_RULE_EVAL,
            static_cast<snort::IpsContext*>(context)->packet,
            "Fast pattern processing - no matches found\n");
#endif
    unsigned i = 0;
    for ( auto it : queue )
    {
        Node& node = it;
        i++;
        // process a pattern - case is handled by otn processing
        debug_logf(detection_trace, TRACE_RULE_EVAL,
            static_cast<snort::IpsContext*>(context)->packet,
            "Processing pattern match #%d\n", i);
        int res = match(node.user, node.tree, node.index, context, node.list);

        if ( res > 0 )
        {
            /* terminate matching */
            pmqs.tot_inq_flush += i;
            queue.clear();
            return true;
        }
    }
    pmqs.tot_inq_flush += i;
    queue.clear();
    return false;
}

void fp_set_context(IpsContext& c)
{
    FastPatternConfig* fp = c.conf->fast_pattern_config;
    c.stash = new MpseStash(fp->get_queue_limit());
    c.otnx = (OtnxMatchData*)snort_calloc(sizeof(OtnxMatchData));
    c.otnx->matchInfo = (MatchInfo*)snort_calloc(MAX_NUM_RULE_TYPES, sizeof(MatchInfo));
    c.context_num = 0;
}

void fp_clear_context(IpsContext& c)
{
    delete c.stash;
    snort_free(c.otnx->matchInfo);
    snort_free(c.otnx);
}

// rule_tree_match() could be used instead to bypass the queuing
static int rule_tree_queue(
    void* user, void* tree, int index, void* context, void* list)
{
    MpseStash* stash = ((IpsContext*)context)->stash;

    if ( stash->push(user, tree, index, list) )
    {
        if ( stash->process(rule_tree_match, context) )
            return 1;
    }
    return 0;
}

static inline int batch_search(
    MpseGroup* so, Packet* p, const uint8_t* buf, unsigned len, PegCount& cnt)
{
    assert(so->get_normal_mpse()->get_pattern_count() > 0);
    cnt++;

    // FIXIT-P Batch outer UDP payload searches for teredo set and the outer header
    // during any signature evaluation
    if ( p->is_udp_tunneled() )
    {
        fp_immediate(so, p, buf, len);
    }
    else
    {
        MpseBatchKey<> key = MpseBatchKey<>(buf, len);
        p->context->searches.items[key].so.push_back(so);
    }

    dump_buffer(buf, len, p);

    if ( PacketLatency::fastpath() )
        return 1;
    return 0;
}

static inline int search_buffer(
    Inspector* gadget, InspectionBuffer& buf, InspectionBuffer::Type ibt,
    Packet* p, PortGroup* pg, PmType pmt, PegCount& cnt)
{
    if ( gadget->get_fp_buf(ibt, p, buf) )
    {
        // Depending on where we are searching we call the appropriate mpse
        if ( MpseGroup* so = pg->mpsegrp[pmt] )
        {
            debug_logf(detection_trace, TRACE_FP_SEARCH, p,
                "%" PRIu64 " fp %s.%s[%d]\n", p->context->packet_number,
                gadget->get_name(), pm_type_strings[pmt], buf.len);

            batch_search(so, p, buf.data, buf.len, cnt);
        }
    }
    return 0;
}

static int fp_search(PortGroup* port_group, Packet* p)
{
    Inspector* gadget = p->flow ? p->flow->gadget : nullptr;
    InspectionBuffer buf;

    debug_log(detection_trace, TRACE_RULE_EVAL, p, "Fast pattern search\n");

    if ( p->data and p->dsize )
    {
        // ports search raw packet only
        if ( MpseGroup* so = port_group->mpsegrp[PM_TYPE_PKT] )
        {
            if ( uint16_t pattern_match_size = p->get_detect_limit() )
            {
                debug_logf(detection_trace, TRACE_FP_SEARCH, p,
                    "%" PRIu64 " fp %s[%u]\n", p->context->packet_number,
                    pm_type_strings[PM_TYPE_PKT], pattern_match_size);

                batch_search(so, p, p->data, pattern_match_size, pc.pkt_searches);
                p->is_cooked() ?  pc.cooked_searches++ : pc.raw_searches++;
            }
        }
    }

    if ( gadget )
    {
        // service searches PDU buffers and file
        if ( search_buffer(gadget, buf, buf.IBT_KEY, p, port_group, PM_TYPE_KEY, pc.key_searches) )
            return 1;

        if ( search_buffer(gadget, buf, buf.IBT_HEADER, p, port_group, PM_TYPE_HEADER, pc.header_searches) )
            return 1;

        if ( search_buffer(gadget, buf, buf.IBT_BODY, p, port_group, PM_TYPE_BODY, pc.body_searches) )
            return 1;

        // FIXIT-L PM_TYPE_ALT will never be set unless we add
        // norm_data keyword or telnet, rpc_decode, smtp keywords
        // until then we must use the standard packet mpse
        if ( search_buffer(gadget, buf, buf.IBT_ALT, p, port_group, PM_TYPE_PKT, pc.alt_searches) )
            return 1;
    }

    {
        // file searches file only
        if ( MpseGroup* so = port_group->mpsegrp[PM_TYPE_FILE] )
        {
            // FIXIT-M file data should be obtained from
            // inspector gadget as is done with search_buffer
            DataPointer file_data = p->context->file_data;

            if ( file_data.len )
            {
                debug_logf(detection_trace, TRACE_FP_SEARCH, p,
                    "%" PRIu64 " fp search %s[%d]\n", p->context->packet_number,
                    pm_type_strings[PM_TYPE_FILE], file_data.len);

                batch_search(so, p, file_data.data, file_data.len, pc.file_searches);
            }
        }
    }
    return 0;
}

static inline void eval_fp(
    PortGroup* port_group, Packet* p, char ip_rule)
{
    const uint8_t* tmp_payload = nullptr;
    uint16_t tmp_dsize = 0;

    if ( !ip_rule )
        p->packet_flags &= ~PKT_IP_RULE;

    else
    {
        int8_t curr_ip_layer = 0;

        tmp_payload = p->data;  // FIXIT-M restore even with offload
        tmp_dsize = p->dsize;

        if (layer::set_outer_ip_api(p, p->ptrs.ip_api, curr_ip_layer))
        {
            p->data = p->ptrs.ip_api.ip_data();
            p->dsize = p->ptrs.ip_api.pay_len();
            p->packet_flags |= PKT_IP_RULE;
        }
    }

    if ( DetectionEngine::content_enabled(p) )
    {
        FastPatternConfig* fp = p->context->conf->fast_pattern_config;

        if ( fp->get_stream_insert() || !(p->packet_flags & PKT_STREAM_INSERT) )
            if ( fp_search(port_group, p) )
                return;
    }
    if ( ip_rule )
    {
        p->data = tmp_payload;
        p->dsize = tmp_dsize;
    }
}

static inline void eval_nfp(
    PortGroup* port_group, Packet* p, char ip_rule)
{
    bool repeat = false;
    int8_t curr_ip_layer = 0;

    const uint8_t* tmp_payload = nullptr;
    uint16_t tmp_dsize = 0;

    FastPatternConfig* fp = p->context->conf->fast_pattern_config;

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
    do
    {
        if (port_group->nfp_rule_count)
        {
            // walk and test the nfp OTNs
            if ( fp->get_debug_print_nc_rules() )
                LogMessage("NC-testing %u rules\n", port_group->nfp_rule_count);

            detection_option_eval_data_t eval_data;

            eval_data.p = p;
            eval_data.pmd = nullptr;
            eval_data.flowbit_failed = 0;
            eval_data.flowbit_noalert = 0;

            int rval = 0;
            {
                debug_log(detection_trace, TRACE_RULE_EVAL, p,
                    "Testing non-content rules\n");
                rval = detection_option_tree_evaluate(
                    (detection_option_tree_root_t*)port_group->nfp_tree, eval_data);
            }

            if (rval)
                pmqs.qualified_events++;
            else
                pmqs.non_qualified_events++;

            pc.hard_evals++;
        }

        // FIXIT-L should really be logging any events based on curr_ip_layer
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
}

//  This function does a set-wise match on content, and walks an otn list
//  for non-content.  The otn list search will eventually be redone for
//  for performance purposes.

static inline int fpEvalHeaderSW(PortGroup* port_group, Packet* p, char ip_rule, FPTask task)
{
    if ( !p->is_detection_enabled(p->packet_flags & PKT_FROM_CLIENT) )
        return 0;

    if ( task & FPTask::FP )
        eval_fp(port_group, p, ip_rule);

    if ( task & FPTask::NON_FP )
        eval_nfp(port_group, p, ip_rule);

    return 0;
}

static inline void fpEvalHeaderIp(Packet* p, FPTask task)
{
    PortGroup* any = nullptr, * ip_group = nullptr;

    if ( !prmFindRuleGroupIp(p->context->conf->prmIpRTNX, ANYPORT, &ip_group, &any) )
        return;

    if ( p->context->conf->fast_pattern_config->get_debug_print_nc_rules() )
        LogMessage("fpEvalHeaderIp: ip_group=%p, any=%p\n", (void*)ip_group, (void*)any);

    if ( ip_group )
        fpEvalHeaderSW(ip_group, p, 1, task);

    if ( any )
        fpEvalHeaderSW(any, p, 1, task);
}

static inline void fpEvalHeaderIcmp(Packet* p, FPTask task)
{
    PortGroup* any = nullptr, * type = nullptr;

    if ( !prmFindRuleGroupIcmp(p->context->conf->prmIcmpRTNX, p->ptrs.icmph->type, &type, &any) )
        return;

    if ( type )
        fpEvalHeaderSW(type, p, 0, task);

    if ( any )
        fpEvalHeaderSW(any, p, 0, task);
}

static inline void fpEvalHeaderTcp(Packet* p, FPTask task)
{
    PortGroup* src = nullptr, * dst = nullptr, * any = nullptr;

    if ( !prmFindRuleGroupTcp(p->context->conf->prmTcpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &any) )
        return;

    if ( dst )
        fpEvalHeaderSW(dst, p, 0, task);

    if ( src )
        fpEvalHeaderSW(src, p, 0, task);

    if ( any )
        fpEvalHeaderSW(any, p, 0, task);
}

static inline void fpEvalHeaderUdp(Packet* p, FPTask task)
{
    PortGroup* src = nullptr, * dst = nullptr, * any = nullptr;

    if ( !prmFindRuleGroupUdp(p->context->conf->prmUdpRTNX, p->ptrs.dp, p->ptrs.sp, &src, &dst, &any) )
        return;

    if ( dst )
        fpEvalHeaderSW(dst, p, 0, task);

    if ( src )
        fpEvalHeaderSW(src, p, 0, task);

    if ( any )
        fpEvalHeaderSW(any, p, 0, task);
}

static inline bool fpEvalHeaderSvc(Packet* p, FPTask task)
{
    PortGroup* svc = nullptr;

    SnortProtocolId snort_protocol_id = p->get_snort_protocol_id();

    if (snort_protocol_id != UNKNOWN_PROTOCOL_ID and snort_protocol_id != INVALID_PROTOCOL_ID)
    {
        if (p->is_from_server()) /* to cli */
            svc = p->context->conf->sopgTable->get_port_group(false, snort_protocol_id);

        if (p->is_from_client()) /* to srv */
            svc = p->context->conf->sopgTable->get_port_group(true, snort_protocol_id);
    }

    if ( svc )
        fpEvalHeaderSW(svc, p, 0, task);

    return svc != nullptr;
}

static void fpEvalPacketUdp(Packet* p, FPTask task)
{
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

    auto save_detect = DetectionEngine::get_detects(p);

    if ( p->dsize )
        DetectionEngine::enable_content(p);

    fpEvalHeaderUdp(p, task);

    // FIXIT-P Batch outer UDP payload searches for teredo set and the outer header
    // during any signature evaluation
    fp_immediate(p);

    p->ptrs.sp = tmp_sp;
    p->ptrs.dp = tmp_dp;
    p->ptrs.udph = tmp_udph;
    p->data = tmp_data;
    p->dsize = tmp_dsize;

    DetectionEngine::set_detects(p, save_detect);
}

/*
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
*/
static void fpEvalPacket(Packet* p, FPTask task)
{
    /* Run UDP rules against the UDP header of Teredo packets */
    // FIXIT-L udph is always inner; need to check for outer
    if ( p->is_udp_tunneled() )
        fpEvalPacketUdp(p, task);

    if ( p->get_snort_protocol_id() != UNKNOWN_PROTOCOL_ID and fpEvalHeaderSvc(p, task) )
        return;

    switch (p->type())
    {
    case PktType::IP:
        fpEvalHeaderIp(p, task);
        break;

    case PktType::ICMP:
        fpEvalHeaderIcmp(p, task);
        break;

    case PktType::TCP:
        fpEvalHeaderTcp(p, task);
        break;

    case PktType::UDP:
        fpEvalHeaderUdp(p, task);
        break;

    case PktType::PDU:
        if ( p->proto_bits & PROTO_BIT__TCP )
            fpEvalHeaderTcp(p, task);

        else if ( p->proto_bits & PROTO_BIT__UDP )
            fpEvalHeaderUdp(p, task);
        break;

    default:
        break;
    }
}

void fp_partial(Packet* p)
{
    Profile mpse_profile(mpsePerfStats);
    IpsContext* c = p->context;
    MpseStash* stash = c->stash;
    stash->enable_process();
    stash->init();
    stash->disable_process();
    init_match_info(c);
    c->searches.mf = rule_tree_queue;
    c->searches.context = c;
    assert(!c->searches.items.size());
    print_pkt_info(p, "fast-patterns");
    fpEvalPacket(p, FPTask::FP);
}

void fp_complete(Packet* p, bool search)
{
    IpsContext* c = p->context;
    MpseStash* stash = c->stash;
    stash->enable_process();

    if ( search )
    {
        Profile mpse_profile(mpsePerfStats);
        c->searches.search_sync();
    }
    {
        Profile rule_profile(rulePerfStats);
        stash->process(rule_tree_match, c);
        print_pkt_info(p, "non-fast-patterns");
        fpEvalPacket(p, FPTask::NON_FP);
        fpFinalSelectEvent(c->otnx, p);
        c->searches.items.clear();
    }
}

void fp_full(Packet* p)
{
    fp_partial(p);
    fp_complete(p, true);
}

static void fp_immediate(Packet* p)
{
    IpsContext* c = p->context;
    MpseStash* stash = c->stash;
    {
        Profile mpse_profile(mpsePerfStats);
        stash->enable_process();
        c->searches.search_sync();
    }
    {
        Profile rule_profile(rulePerfStats);
        stash->process(rule_tree_match, c);
        c->searches.items.clear();
    }
}

static void fp_immediate(MpseGroup* so, Packet* p, const uint8_t* buf, unsigned len)
{
    MpseStash* stash = p->context->stash;
    {
        Profile mpse_profile(mpsePerfStats);
        int start_state = 0;
        stash->init();
        so->get_normal_mpse()->search(buf, len, rule_tree_queue, p->context, &start_state);
    }
    {
        Profile rule_profile(rulePerfStats);
        stash->process(rule_tree_match, p->context);
    }
}

