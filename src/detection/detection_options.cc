//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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
**  @file        detection_options.c
**  @author      Steven Sturges
**  @brief       Support functions for rule option tree
**
**  This implements tree processing for rule options, evaluating common
**  detection options only once per pattern match.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection_options.h"

#include <string>

#include "filters/detection_filter.h"
#include "framework/cursor.h"
#include "hash/hashfcn.h"
#include "hash/xhash.h"
#include "ips_options/extract.h"
#include "ips_options/ips_flowbits.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency_state.h"
#include "log/messages.h"
#include "main/modules.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/thread_config.h"
#include "managers/ips_manager.h"
#include "parser/parser.h"
#include "profiler/rule_profiler_defs.h"
#include "protocols/packet_manager.h"
#include "utils/util.h"

#include "detection_engine.h"
#include "detection_util.h"
#include "detect_trace.h"
#include "fp_create.h"
#include "fp_detect.h"
#include "ips_context.h"
#include "pattern_match_data.h"
#include "rules.h"
#include "treenodes.h"

using namespace snort;

#define HASH_RULE_OPTIONS 16384
#define HASH_RULE_TREE     8192

#define HASH_EQUAL        0
#define HASH_NOT_EQUAL    1

struct detection_option_key_t
{
    option_type_t option_type;
    void* option_data;
};

// FIXIT-L find a better place for this
static inline bool operator==(const struct timeval& a, const struct timeval& b)
{ return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec; }

static uint32_t detection_option_hash_func(HashFnc*, const unsigned char* k, int)
{
    const detection_option_key_t* key = (const detection_option_key_t*)k;

    if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt = (IpsOption*)key->option_data;
        return opt->hash();
    }
    return 0;
}

static int detection_option_key_compare_func(const void* k1, const void* k2, size_t)
{
    const detection_option_key_t* key1 = (const detection_option_key_t*)k1;
    const detection_option_key_t* key2 = (const detection_option_key_t*)k2;

    if ( !key1 || !key2 )
        return HASH_NOT_EQUAL;

    if ( key1->option_type != key2->option_type )
        return HASH_NOT_EQUAL;

    if ( key1->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt1 = (IpsOption*)key1->option_data;
        IpsOption* opt2 = (IpsOption*)key2->option_data;

        if ( *opt1 == *opt2 )
            return HASH_EQUAL;
    }
    return HASH_NOT_EQUAL;
}

static int detection_hash_free_func(void* option_key, void*)
{
    detection_option_key_t* key = (detection_option_key_t*)option_key;

    if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt = (IpsOption*)key->option_data;
        IpsManager::delete_option(opt);
    }
    return 0;
}

static XHash* DetectionHashTableNew()
{
    XHash* doht = xhash_new(HASH_RULE_OPTIONS,
        sizeof(detection_option_key_t),
        0,                              /* Data size == 0, just store the ptr */
        0,                              /* Memcap */
        0,                              /* Auto node recovery */
        nullptr,                           /* Auto free function */
        detection_hash_free_func,                           /* User free function */
        1);                             /* Recycle nodes */

    if (doht == nullptr)
        FatalError("Failed to create rule detection option hash table");

    xhash_set_keyops(doht, detection_option_hash_func, detection_option_key_compare_func);

    return doht;
}

void DetectionHashTableFree(XHash* doht)
{
    if (doht != nullptr)
        xhash_delete(doht);
}

void* add_detection_option(SnortConfig* sc, option_type_t type, void* option_data)
{
    if ( !sc->detection_option_hash_table )
        sc->detection_option_hash_table = DetectionHashTableNew();

    detection_option_key_t key;
    key.option_type = type;
    key.option_data = option_data;

    if ( void* p = xhash_find(sc->detection_option_hash_table, &key) )
        return p;

    xhash_add(sc->detection_option_hash_table, &key, option_data);
    return nullptr;
}

static uint32_t detection_option_tree_hash(detection_option_tree_node_t* node)
{
    uint32_t a,b,c;
    int i;

    if (!node)
        return 0;

    a = b = c = 0;

    for (i=0; i<node->num_children; i++)
    {
#if (defined(__ia64) || defined(__amd64) || defined(_LP64))
        {
            /* Cleanup warning because of cast from 64bit ptr to 32bit int
             * warning on 64bit OSs */
            uint64_t ptr; /* Addresses are 64bits */
            ptr = (uint64_t)node->children[i]->option_data;
            a += (ptr >> 32);
            b += (ptr & 0xFFFFFFFF);
        }
#else
        a += (uint32_t)node->children[i]->option_data;
        b += 0;
#endif
        c += detection_option_tree_hash(node->children[i]);
        mix(a,b,c);
        a += node->children[i]->num_children;
        mix(a,b,c);
#if 0
        a += (uint32_t)node->children[i]->option_data;
        /* Recurse & hash up this guy's children */
        b += detection_option_tree_hash(node->children[i]);
        c += node->children[i]->num_children;
        mix(a,b,c);
#endif
    }

    finalize(a,b,c);

    return c;
}

static uint32_t detection_option_tree_hash_func(HashFnc*, const unsigned char* k, int)
{
    const detection_option_key_t* key = (const detection_option_key_t*)k;
    detection_option_tree_node_t* node;

    if (!key || !key->option_data)
        return 0;

    node = (detection_option_tree_node_t*)key->option_data;

    return detection_option_tree_hash(node);
}

static bool detection_option_tree_compare(
    const detection_option_tree_node_t* r, const detection_option_tree_node_t* l)
{
    if ( !r and !l )
        return HASH_EQUAL;

    if ( !r or !l )
        return HASH_NOT_EQUAL;

    if ( r->option_data != l->option_data )
        return HASH_NOT_EQUAL;

    if ( r->num_children != l->num_children )
        return HASH_NOT_EQUAL;

    for ( int i=0; i<r->num_children; i++ )
    {
        /* Recurse & check the children for equality */
        int ret = detection_option_tree_compare(r->children[i], l->children[i]);

        if ( ret != HASH_EQUAL )
            return ret;
    }

    return HASH_EQUAL;
}

static int detection_option_tree_compare_func(const void* k1, const void* k2, size_t)
{
    const detection_option_key_t* key_r = (const detection_option_key_t*)k1;
    const detection_option_key_t* key_l = (const detection_option_key_t*)k2;

    if ( !key_r or !key_l )
        return HASH_NOT_EQUAL;

    const detection_option_tree_node_t* r = (const detection_option_tree_node_t*)key_r->option_data;
    const detection_option_tree_node_t* l = (const detection_option_tree_node_t*)key_l->option_data;

    return detection_option_tree_compare(r, l);
}

static int detection_option_tree_free_func(void*, void* data)
{
    detection_option_tree_node_t* node = (detection_option_tree_node_t*)data;
    free_detection_option_tree(node);
    return 0;
}

void DetectionTreeHashTableFree(XHash* dtht)
{
    if (dtht != nullptr)
        xhash_delete(dtht);
}

static XHash* DetectionTreeHashTableNew()
{
    XHash* dtht = xhash_new(
        HASH_RULE_TREE,
        sizeof(detection_option_key_t),
        0,      /* Data size == 0, just store the ptr */
        0,      /* Memcap */
        0,      /* Auto node recovery */
        nullptr,   /* Auto free function */
        detection_option_tree_free_func,   /* User free function */
        1);     /* Recycle nodes */

    if (dtht == nullptr)
        FatalError("Failed to create rule detection option hash table");

    xhash_set_keyops(dtht, detection_option_tree_hash_func, detection_option_tree_compare_func);

    return dtht;
}

void print_option_tree(detection_option_tree_node_t* node, int level)
{
#ifdef DEBUG_MSGS
    char buf[32];
    const char* opt;

    if ( node->option_type != RULE_OPTION_TYPE_LEAF_NODE )
        opt = ((IpsOption*)node->option_data)->get_name();
    else
    {
        const OptTreeNode* otn = (OptTreeNode*)node->option_data;
        const SigInfo& si = otn->sigInfo;
        snprintf(buf, sizeof(buf), "%u:%u:%u", si.gid, si.sid, si.rev);
        opt = buf;
    }

    trace_logf(detection, TRACE_OPTION_TREE, "%3d %3d  %p %*s\n",
        level, node->num_children, node->option_data, (int)(level + strlen(opt)), opt);

    for ( int i=0; i<node->num_children; i++ )
        print_option_tree(node->children[i], level+1);
#else
    UNUSED(node);
    UNUSED(level);
#endif
}

void* add_detection_option_tree(SnortConfig* sc, detection_option_tree_node_t* option_tree)
{
    if ( !sc->detection_option_tree_hash_table )
        sc->detection_option_tree_hash_table = DetectionTreeHashTableNew();

    detection_option_key_t key;
    key.option_data = (void*)option_tree;
    key.option_type = RULE_OPTION_TYPE_LEAF_NODE;

    if ( void* p = xhash_find(sc->detection_option_tree_hash_table, &key) )
        return p;

    xhash_add(sc->detection_option_tree_hash_table, &key, option_tree);
    return nullptr;
}

int detection_option_node_evaluate(
    detection_option_tree_node_t* node, detection_option_eval_data_t* eval_data,
    Cursor& orig_cursor)
{
    // need node->state to do perf profiling
    if ( !node )
        return 0;

    auto& state = node->state[get_instance_id()];
    RuleContext profile(state);

    int result = 0;
    int rval = (int)IpsOption::NO_MATCH;  // FIXIT-L refactor to eliminate casts to int
    char tmp_noalert_flag = 0;
    Cursor cursor = orig_cursor;
    bool continue_loop = true;
    char flowbits_setoperation = 0;
    int loop_count = 0;
    uint32_t tmp_byte_extract_vars[NUM_IPS_OPTIONS_VARS];
    uint64_t cur_eval_context_num = DetectionEngine::get_context()->context_num;

    if ( !eval_data || !eval_data->p || !eval_data->pomd )
        return 0;

    node_eval_trace(node, cursor, eval_data->p);

    auto p = eval_data->p;
    auto pomd = eval_data->pomd;

    // see if evaluated it before ...
    if ( !node->is_relative )
    {
        auto last_check = state.last_check;

        if ( last_check.ts == p->pkth->ts &&
            last_check.run_num == get_run_num() &&
            last_check.context_num == cur_eval_context_num &&
            last_check.rebuild_flag == (p->packet_flags & PKT_REBUILT_STREAM) &&
            !(p->packet_flags & PKT_ALLOW_MULTIPLE_DETECT) )
        {
            if ( !last_check.flowbit_failed &&
                !(p->packet_flags & PKT_IP_RULE_2ND) &&
                !(p->proto_bits & (PROTO_BIT__TEREDO|PROTO_BIT__GTP)) )
            {
                trace_log(detection, TRACE_RULE_EVAL,
                    "Was evaluated before, returning last check result\n");
                return last_check.result;
            }
        }
    }

    state.last_check.ts = eval_data->p->pkth->ts;
    state.last_check.run_num = get_run_num();
    state.last_check.context_num = cur_eval_context_num;
    state.last_check.flowbit_failed = 0;
    state.last_check.rebuild_flag = p->packet_flags & PKT_REBUILT_STREAM;

    // Save some stuff off for repeated pattern tests
    PmdLastCheck* content_last = nullptr;

    if ( node->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        IpsOption* opt = (IpsOption*)node->option_data;
        PatternMatchData* pmd = opt->get_pattern(0, RULE_WO_DIR);

        if ( pmd and pmd->last_check )
            content_last = pmd->last_check + get_instance_id();
    }

    // No, haven't evaluated this one before... Check it.
    do
    {
        switch ( node->option_type )
        {
        case RULE_OPTION_TYPE_LEAF_NODE:
            // Add the match for this otn to the queue.
        {
            OptTreeNode* otn = (OptTreeNode*)node->option_data;
            SnortProtocolId snort_protocol_id = p->get_snort_protocol_id();
            int check_ports = 1;

            if ( snort_protocol_id != UNKNOWN_PROTOCOL_ID and ((OtnxMatchData*)(pomd))->check_ports != 2 )
            {
                auto sig_info = otn->sigInfo;

                for ( unsigned svc_idx = 0; svc_idx < sig_info.num_services; ++svc_idx )
                {
                    if ( snort_protocol_id == sig_info.services[svc_idx].snort_protocol_id )
                    {
                        check_ports = 0;
                        break;  // out of for
                    }
                }

                if (sig_info.num_services && check_ports)
                {
                    // none of the services match
                    trace_logf(detection, TRACE_RULE_EVAL,
                        "SID %u not matched because of service mismatch %d!=%d \n",
                        sig_info.sid, snort_protocol_id, sig_info.services[0].snort_protocol_id);
                    break;  // out of case
                }
            }

            int eval_rtn_result = 0;

            // Don't include RTN time
            {
                RulePause pause(profile);
                eval_rtn_result = fpEvalRTN(getRuntimeRtnFromOtn(otn), p, check_ports);
            }

            if ( eval_rtn_result )
            {
                bool f_result = true;

                if ( otn->detection_filter )
                {
                    trace_log(detection, TRACE_RULE_EVAL,
                        "Evaluating detection filter\n");
                    f_result = !detection_filter_test(otn->detection_filter,
                        p->ptrs.ip_api.get_src(), p->ptrs.ip_api.get_dst(),
                        p->pkth->ts.tv_sec);
                }

                if ( f_result )
                {
                    otn->state[get_instance_id()].matches++;

                    if ( !eval_data->flowbit_noalert )
                    {
                        PatternMatchData* pmd = (PatternMatchData*)eval_data->pmd;
                        int pattern_size = pmd ? pmd->pattern_size : 0;
#ifdef DEBUG_MSGS
                        const SigInfo& si = otn->sigInfo;
                        trace_logf(detection, TRACE_RULE_EVAL,
                            "Matched rule gid:sid:rev %u:%u:%u\n", si.gid, si.sid, si.rev);
#endif

                        fpAddMatch((OtnxMatchData*)pomd, pattern_size, otn);
                    }
                    result = rval = (int)IpsOption::MATCH;
                }
            }
#ifdef DEBUG_MSGS
            else
                trace_log(detection, TRACE_RULE_EVAL, "Header check failed\n");
#endif

            break;
        }

        case RULE_OPTION_TYPE_CONTENT:
            if ( node->evaluate )
            {
                // This will be set in the fast pattern matcher if we found
                // a content and the rule option specifies not that
                // content. Essentially we've already evaluated this rule
                // option via the content option processing since only not
                // contents that are not relative in any way will have this
                // flag set
                if ( content_last )
                {
                    if ( content_last->ts == p->pkth->ts &&
                        content_last->run_num == get_run_num() &&
                        content_last->context_num == cur_eval_context_num &&
                        content_last->rebuild_flag == (p->packet_flags & PKT_REBUILT_STREAM) )
                    {
                        rval = (int)IpsOption::NO_MATCH;
                        break;
                    }
                }
                rval = node->evaluate(node->option_data, cursor, p);
            }
            break;

        case RULE_OPTION_TYPE_FLOWBIT:
            if ( node->evaluate )
            {
                flowbits_setoperation = FlowBits_SetOperation(node->option_data);

                if ( flowbits_setoperation )
                    // set to match so we don't bail early
                    rval = (int)IpsOption::MATCH;

                else
                    rval = node->evaluate(node->option_data, cursor, eval_data->p);
            }
            break;

        default:
            if ( node->evaluate )
                rval = node->evaluate(node->option_data, cursor, p);
            break;
        }

        if ( rval == (int)IpsOption::NO_MATCH )
        {
            trace_log(detection, TRACE_RULE_EVAL, "no match\n");
            state.last_check.result = result;
            return result;
        }
        else if ( rval == (int)IpsOption::FAILED_BIT )
        {
            trace_log(detection, TRACE_RULE_EVAL, "failed bit\n");
            eval_data->flowbit_failed = 1;
            // clear the timestamp so failed flowbit gets eval'd again
            state.last_check.flowbit_failed = 1;
            state.last_check.result = result;
            return 0;
        }
        else if ( rval == (int)IpsOption::NO_ALERT )
        {
            // Cache the current flowbit_noalert flag, and set it
            // so nodes below this don't alert.
            tmp_noalert_flag = eval_data->flowbit_noalert;
            eval_data->flowbit_noalert = 1;
            trace_log(detection, TRACE_RULE_EVAL, "flowbit no alert\n");
        }

        // Back up byte_extract vars so they don't get overwritten between rules
        trace_log(detection, TRACE_RULE_VARS, "Rule options variables: \n");
        for ( int i = 0; i < NUM_IPS_OPTIONS_VARS; ++i )
        {
            GetVarValueByIndex(&(tmp_byte_extract_vars[i]), (int8_t)i);
            trace_logf_wo_name(detection, TRACE_RULE_VARS, "var[%d]=%d ", i,
                tmp_byte_extract_vars[i]);
        }
        trace_log_wo_name(detection, TRACE_RULE_VARS, "\n");

        if ( PacketLatency::fastpath() )
        {
            profile.stop(result != (int)IpsOption::NO_MATCH);
            state.last_check.result = result;
            return result;
        }

        {
            RulePause pause(profile);
            // Passed, check the children.
            if ( node->num_children )
            {
                for ( int i = 0; i < node->num_children; ++i )
                {
                    detection_option_tree_node_t* child_node = node->children[i];
                    dot_node_state_t* child_state = child_node->state + get_instance_id();

                    for ( int j = 0; j < NUM_IPS_OPTIONS_VARS; ++j )
                        SetVarValueByIndex(tmp_byte_extract_vars[j], (int8_t)j);

                    if ( loop_count > 0 )
                    {
                        if ( child_state->result == (int)IpsOption::NO_MATCH )
                        {
                            if ( child_node->option_type == RULE_OPTION_TYPE_CONTENT )
                            {
                                if ( !child_node->is_relative )
                                {
                                    // If it's a non-relative content or pcre, no reason
                                    // to check again.  Only increment result once.
                                    // Should hit this condition on first loop iteration.
                                    if ( loop_count == 1 )
                                        ++result;

                                    continue;
                                }
                                else
                                {
                                    // Check for an unbounded relative search.  If this
                                    // failed before, it's going to fail again so don't
                                    // go down this path again
                                    IpsOption* opt = (IpsOption*)child_node->option_data;
                                    PatternMatchData* pmd = opt->get_pattern(0, RULE_WO_DIR);

                                    if ( pmd and pmd->is_unbounded() )
                                    {
                                        // Only increment result once. Should hit this
                                        // condition on first loop iteration
                                        if (loop_count == 1)
                                            ++result;

                                        continue;
                                    }
                                }
                            }
                        }
                        else if ( child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
                            // Leaf node matched, don't eval again
                            continue;

                        else if ( child_state->result == child_node->num_children )
                            // This branch of the tree matched or has options that
                            // don't need to be evaluated again, so don't need to
                            // evaluate this option again
                            continue;
                    }

                    child_state->result = detection_option_node_evaluate(
                        node->children[i], eval_data, cursor);

                    if ( child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
                        // Leaf node won't have any children but will return success
                        // or failure
                        result += child_state->result;

                    else if (child_state->result == child_node->num_children)
                        // Indicate that the child's tree branches are done
                        ++result;

                    if ( PacketLatency::fastpath() )
                    {
                        state.last_check.result = result;
                        return result;
                    }
                }

                // If all children branches matched, we don't need to reeval any of
                // the children so don't need to reeval this content/pcre rule
                // option at a new offset.
                // Else, reset the DOE ptr to last eval for offset/depth,
                // distance/within adjustments for this same content/pcre
                // rule option
                if ( result == node->num_children )
                    continue_loop = false;

                // Don't need to reset since it's only checked after we've gone
                // through the loop at least once and the result will have
                // been set again already
                //for (i = 0; i < node->num_children; i++)
                //    node->children[i]->result;
            }
        }

        if ( rval == (int)IpsOption::NO_ALERT )
        {
            // Reset the flowbit_noalert flag in eval data
            eval_data->flowbit_noalert = tmp_noalert_flag;
        }

        if ( continue_loop && rval == (int)IpsOption::MATCH && node->relative_children )
        {
            IpsOption* opt = (IpsOption*)node->option_data;
            continue_loop = opt->retry(cursor);
        }
        else
            continue_loop = false;

        // We're essentially checking this node again and it potentially
        // might match again
        if ( continue_loop )
            state.checks++;

        loop_count++;
    }
    while ( continue_loop );

    if ( flowbits_setoperation && result == (int)IpsOption::MATCH )
    {
        // Do any setting/clearing/resetting/toggling of flowbits here
        // given that other rule options matched
        rval = node->evaluate(node->option_data, cursor, p);
        if ( rval != (int)IpsOption::MATCH )
            result = rval;
    }

    if ( eval_data->flowbit_failed )
    {
        // something deeper in the tree failed a flowbit test, we may need to
        // reeval this node
        state.last_check.flowbit_failed = 1;
    }

    state.last_check.result = result;
    profile.stop(result != (int)IpsOption::NO_MATCH);

    return result;
}

struct node_profile_stats
{
    // FIXIT-L duplicated from dot_node_state_t and OtnState
    hr_duration elapsed;
    hr_duration elapsed_match;
    hr_duration elapsed_no_match;

    uint64_t checks;
    uint64_t latency_timeouts;
    uint64_t latency_suspends;
};

static void detection_option_node_update_otn_stats(detection_option_tree_node_t* node,
    node_profile_stats* stats, uint64_t checks, uint64_t timeouts, uint64_t suspends)
{
    node_profile_stats local_stats; /* cumulative stats for this node */
    node_profile_stats node_stats;  /* sum of all instances */

    memset(&node_stats, 0, sizeof(node_stats));

    for ( unsigned i = 0; i < ThreadConfig::get_instance_max(); ++i )
    {
        node_stats.elapsed += node->state[i].elapsed;
        node_stats.elapsed_match += node->state[i].elapsed_match;
        node_stats.elapsed_no_match += node->state[i].elapsed_no_match;
        node_stats.checks += node->state[i].checks;
    }

    if ( stats )
    {
        local_stats.elapsed = stats->elapsed + node_stats.elapsed;
        local_stats.elapsed_match = stats->elapsed_match + node_stats.elapsed_match;
        local_stats.elapsed_no_match = stats->elapsed_no_match + node_stats.elapsed_no_match;

        if (node_stats.checks > stats->checks)
            local_stats.checks = node_stats.checks;
        else
            local_stats.checks = stats->checks;

        local_stats.latency_timeouts = timeouts;
        local_stats.latency_suspends = suspends;
    }
    else
    {
        local_stats.elapsed = node_stats.elapsed;
        local_stats.elapsed_match = node_stats.elapsed_match;
        local_stats.elapsed_no_match = node_stats.elapsed_no_match;
        local_stats.checks = node_stats.checks;
        local_stats.latency_timeouts = timeouts;
        local_stats.latency_suspends = suspends;
    }

    if ( node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
    {
        // Update stats for this otn
        // FIXIT-L call from packet threads at exit or total *all* states by main thread
        // Right now, it looks like we're missing out on some stats although it's possible
        // that this is "corrected" in the profiler code
        auto* otn = (OptTreeNode*)node->option_data;
        auto& state = otn->state[get_instance_id()];

        state.elapsed += local_stats.elapsed;
        state.elapsed_match += local_stats.elapsed_match;
        state.elapsed_no_match += local_stats.elapsed_no_match;

        if (local_stats.checks > state.checks)
            state.checks = local_stats.checks;

        state.latency_timeouts += local_stats.latency_timeouts;
        state.latency_suspends += local_stats.latency_suspends;
    }

    if ( node->num_children )
    {
        for ( int i=0; i < node->num_children; ++i )
            detection_option_node_update_otn_stats(node->children[i], &local_stats, checks,
                timeouts, suspends);
    }
}

void detection_option_tree_update_otn_stats(XHash* doth)
{
    if ( !doth )
        return;

    for ( auto hnode = xhash_findfirst(doth); hnode; hnode = xhash_findnext(doth) )
    {
        auto* node = (detection_option_tree_node_t*)hnode->data;
        assert(node);

        uint64_t checks = 0;
        uint64_t timeouts = 0;
        uint64_t suspends = 0;

        for ( unsigned i = 0; i < ThreadConfig::get_instance_max(); ++i )
        {
            checks += node->state[i].checks;
            timeouts += node->state[i].latency_timeouts;
            suspends += node->state[i].latency_suspends;
        }

        if ( checks )
            detection_option_node_update_otn_stats(node, nullptr, checks, timeouts, suspends);
    }
}

detection_option_tree_root_t* new_root(OptTreeNode* otn)
{
    detection_option_tree_root_t* p = (detection_option_tree_root_t*)
        snort_calloc(sizeof(detection_option_tree_root_t));

    p->latency_state = new RuleLatencyState[ThreadConfig::get_instance_max()]();
    p->otn = otn;

    return p;
}

void free_detection_option_root(void** existing_tree)
{
    detection_option_tree_root_t* root;

    if (!existing_tree || !*existing_tree)
        return;

    root = (detection_option_tree_root_t*)*existing_tree;
    snort_free(root->children);

    delete[] root->latency_state;
    snort_free(root);
    *existing_tree = nullptr;
}

detection_option_tree_node_t* new_node(option_type_t type, void* data)
{
    detection_option_tree_node_t* p =
        (detection_option_tree_node_t*)snort_calloc(sizeof(*p));

    p->option_type = type;
    p->option_data = data;

    p->state = (dot_node_state_t*)
        snort_calloc(ThreadConfig::get_instance_max(), sizeof(*p->state));

    return p;
}

void free_detection_option_tree(detection_option_tree_node_t* node)
{
    int i;
    for (i=0; i<node->num_children; i++)
    {
        free_detection_option_tree(node->children[i]);
    }
    snort_free(node->children);
    snort_free(node->state);
    snort_free(node);
}

