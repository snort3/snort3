//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <mutex>
#include <string>

#include "filters/detection_filter.h"
#include "framework/cursor.h"
#include "hash/hash_defs.h"
#include "hash/hash_key_operations.h"
#include "hash/xhash.h"
#include "ips_options/extract.h"
#include "ips_options/ips_flowbits.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency_state.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/ips_manager.h"
#include "parser/parser.h"
#include "profiler/rule_profiler_defs.h"
#include "protocols/packet_manager.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "detection_continuation.h"
#include "detection_engine.h"
#include "detection_module.h"
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

struct detection_option_key_t
{
    option_type_t option_type;
    void* option_data;
};

// FIXIT-L find a better place for this
static inline bool operator==(const struct timeval& a, const struct timeval& b)
{ return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec; }

class DetectionOptionHashKeyOps : public HashKeyOperations
{
public:
    DetectionOptionHashKeyOps(int rows)
        : HashKeyOperations(rows)
    { }

    unsigned do_hash(const unsigned char* k, int) override
    {
        const detection_option_key_t* key = (const detection_option_key_t*)k;

        if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
        {
            IpsOption* opt = (IpsOption*)key->option_data;
            return opt->hash();
        }
        return 0;
    }

    bool key_compare(const void* k1, const void* k2, size_t) override
    {
        const detection_option_key_t* key1 = (const detection_option_key_t*)k1;
        const detection_option_key_t* key2 = (const detection_option_key_t*)k2;

        assert(key1 && key2);

        if ( key1->option_type != key2->option_type )
            return false;

        if ( key1->option_type != RULE_OPTION_TYPE_LEAF_NODE )
        {
            IpsOption* opt1 = (IpsOption*)key1->option_data;
            IpsOption* opt2 = (IpsOption*)key2->option_data;

            if ( *opt1 == *opt2 )
                return true;
        }
        return false;
    }
};

class DetectionOptionHash : public XHash
{
public:

    DetectionOptionHash(int rows, int key_len)
        : XHash(rows, key_len)
    {
        initialize(new DetectionOptionHashKeyOps(nrows));
    }

    ~DetectionOptionHash() override
    {
        delete_hash_table();
    }

    void free_user_data(HashNode* hnode) override
    {
        detection_option_key_t* key = (detection_option_key_t*)hnode->key;

        if ( key->option_type != RULE_OPTION_TYPE_LEAF_NODE )
        {
            IpsOption* opt = (IpsOption*)key->option_data;
            IpsManager::delete_option(opt);
        }
    }
};

static uint32_t detection_option_tree_hash(detection_option_tree_node_t* node)
{
    assert(node);

    uint32_t a, b, c;
    a = b = c = 0;

    for ( int i = 0; i < node->num_children; i++)
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

static bool detection_option_tree_compare(
    const detection_option_tree_node_t* r, const detection_option_tree_node_t* l)
{
    assert(r and l);

    if ( r->option_data != l->option_data )
        return false;

    if ( r->num_children != l->num_children )
        return false;

    for ( int i = 0; i < r->num_children; i++ )
    {
        /* Recurse & check the children for equality */
        if ( !detection_option_tree_compare(r->children[i], l->children[i]) )
            return false;
    }

    return true;
}

void free_detection_option_tree(detection_option_tree_node_t* node)
{
    for (int i = 0; i < node->num_children; i++)
        free_detection_option_tree(node->children[i]);

    snort_free(node->children);
    snort_free(node->state);
    snort_free(node);
}

class DetectionOptionTreeHashKeyOps : public HashKeyOperations
{
public:
    DetectionOptionTreeHashKeyOps(int rows)
        : HashKeyOperations(rows)
    { }

    unsigned do_hash(const unsigned char* k, int) override
    {
        assert(k);
        const detection_option_key_t* key = (const detection_option_key_t*)k;
        if ( !key->option_data )
            return 0;

        detection_option_tree_node_t* node = (detection_option_tree_node_t*)key->option_data;

        return detection_option_tree_hash(node);
    }

    bool key_compare(const void* k1, const void* k2, size_t) override
    {
        assert(k1 && k2);

        const detection_option_key_t* key_r = (const detection_option_key_t*)k1;
        const detection_option_key_t* key_l = (const detection_option_key_t*)k2;

        const detection_option_tree_node_t* r = (const detection_option_tree_node_t*)key_r->option_data;
        const detection_option_tree_node_t* l = (const detection_option_tree_node_t*)key_l->option_data;

        return detection_option_tree_compare(r, l);
    }
};

class DetectionOptionTreeHash : public XHash
{
public:
    DetectionOptionTreeHash(int rows, int key_len)
        : XHash(rows, key_len)
    {
        initialize(new DetectionOptionTreeHashKeyOps(nrows));
    }

    ~DetectionOptionTreeHash() override
    {
        delete_hash_table();
    }

    void free_user_data(HashNode* hnode) override
    {
        free_detection_option_tree((detection_option_tree_node_t*)hnode->data);
    }

};

static DetectionOptionHash* DetectionHashTableNew()
{
   return new DetectionOptionHash(HASH_RULE_OPTIONS, sizeof(detection_option_key_t));
}

static DetectionOptionTreeHash* DetectionTreeHashTableNew()
{
    return new DetectionOptionTreeHash(HASH_RULE_TREE, sizeof(detection_option_key_t));
}

void* add_detection_option(SnortConfig* sc, option_type_t type, void* option_data)
{
    if ( !sc->detection_option_hash_table )
        sc->detection_option_hash_table = DetectionHashTableNew();

    detection_option_key_t key;
    key.option_type = type;
    key.option_data = option_data;

    if ( void* p = sc->detection_option_hash_table->get_user_data(&key) )
        return p;

    sc->detection_option_hash_table->insert(&key, option_data);
    return nullptr;
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

    const char* srtn = node->otn ? " (rtn)" : "";

    debug_logf(detection_trace, TRACE_OPTION_TREE, nullptr, "%3d %3d  %p %*s%s\n",
        level+1, node->num_children, node->option_data, (int)(level + strlen(opt)), opt, srtn);

    for ( int i=0; i<node->num_children; i++ )
        print_option_tree(node->children[i], level+1);
#else
    UNUSED(node);
    UNUSED(level);
#endif
}

void* add_detection_option_tree(SnortConfig* sc, detection_option_tree_node_t* option_tree)
{
    static std::mutex build_mutex;
    std::lock_guard<std::mutex> lock(build_mutex);

    if ( !sc->detection_option_tree_hash_table )
        sc->detection_option_tree_hash_table = DetectionTreeHashTableNew();

    detection_option_key_t key;
    key.option_data = (void*)option_tree;
    key.option_type = RULE_OPTION_TYPE_LEAF_NODE;

    if ( void* p = sc->detection_option_tree_hash_table->get_user_data(&key) )
        return p;

    sc->detection_option_tree_hash_table->insert(&key, option_tree);
    return nullptr;
}

int detection_option_node_evaluate(
    const detection_option_tree_node_t* node, detection_option_eval_data_t& eval_data,
    const Cursor& orig_cursor)
{
    assert(node and eval_data.p);

    node_eval_trace(node, orig_cursor, eval_data.p);

    auto& state = node->state[get_instance_id()];
    RuleContext profile(state);

    uint64_t cur_eval_context_num = eval_data.p->context->context_num;
    auto p = eval_data.p;

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
                !p->is_udp_tunneled() )
            {
                debug_log(detection_trace, TRACE_RULE_EVAL, p,
                    "Was evaluated before, returning last check result\n");
                return last_check.result;
            }
        }
    }

    state.last_check.ts = eval_data.p->pkth->ts;
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

        if ( pmd and pmd->is_literal() and pmd->last_check )
            content_last = pmd->last_check + get_instance_id();
    }

    bool continue_loop = true;
    int loop_count = 0;

    char tmp_noalert_flag = 0;
    int result = 0;
    uint32_t tmp_byte_extract_vars[NUM_IPS_OPTIONS_VARS];
    IpsOption* buf_selector = eval_data.buf_selector;
    Cursor cursor = orig_cursor;
    int rval;

    // No, haven't evaluated this one before... Check it.
    do
    {
        rval = (int)IpsOption::NO_MATCH;  // FIXIT-L refactor to eliminate casts to int.
        if ( node->otn and !node->otn->sigInfo.file_id )
        {
            SnortProtocolId snort_protocol_id = p->get_snort_protocol_id();
            int check_ports = 1;

            if ( snort_protocol_id != UNKNOWN_PROTOCOL_ID )
            {
                const auto& sig_info = node->otn->sigInfo;

                for ( const auto& svc : sig_info.services )
                {
                    if ( snort_protocol_id == svc.snort_protocol_id )
                    {
                        check_ports = 0;
                        break;  // out of for
                    }
                }

                if ( !sig_info.services.empty() and check_ports )
                {
                    debug_logf(detection_trace, TRACE_RULE_EVAL, p,
                        "SID %u not matched because of service mismatch %d\n",
                        sig_info.sid, snort_protocol_id);
                    break;  // out of case
                }
            }

            if ( !fp_eval_rtn(getRtnFromOtn(node->otn), p, check_ports) )
                break;
        }

        switch ( node->option_type )
        {
        case RULE_OPTION_TYPE_LEAF_NODE:
            {
                OptTreeNode* otn = (OptTreeNode*)node->option_data;
                bool f_result = true;

                if ( otn->detection_filter )
                {
                    debug_log(detection_trace, TRACE_RULE_EVAL, p,
                        "Evaluating detection filter\n");
                    f_result = !detection_filter_test(otn->detection_filter,
                        p->ptrs.ip_api.get_src(), p->ptrs.ip_api.get_dst(),
                        p->pkth->ts.tv_sec);
                }

                if ( !f_result )
                {
                    debug_log(detection_trace, TRACE_RULE_EVAL, p, "Header check failed\n");
                }
                else
                {
                    otn->state[get_instance_id()].matches++;

                    if ( !eval_data.flowbit_noalert )
                    {
#ifdef DEBUG_MSGS
                        const SigInfo& si = otn->sigInfo;
                        debug_logf(detection_trace, TRACE_RULE_EVAL, p,
                            "Matched rule gid:sid:rev %u:%u:%u\n", si.gid, si.sid, si.rev);
#endif
                        fpAddMatch(p->context->otnx, otn);
                    }
                    result = rval = (int)IpsOption::MATCH;
                    eval_data.leaf_reached = 1;
                }
            }
            break;

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
                rval = node->evaluate(node->option_data, cursor, eval_data.p);
                assert((flowbits_setter(node->option_data) and rval == (int)IpsOption::MATCH)
                    or !flowbits_setter(node->option_data));
            }
            break;

        default:
            if ( node->evaluate )
            {
                IpsOption* opt = (IpsOption*)node->option_data;
                if ( opt->is_buffer_setter() )
                    buf_selector = opt;
                rval = node->evaluate(node->option_data, cursor, p);
            }
            break;
        }

        if ( rval == (int)IpsOption::NO_MATCH )
        {
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "no match\n");
            state.last_check.result = result;
            // See if the option has failed due to incomplete input or its failed evaluation
            if (orig_cursor.awaiting_data())
                Continuation::postpone<false>(orig_cursor, *node, eval_data);
            else
                Continuation::postpone<true>(cursor, *node, eval_data);
            return result;
        }
        else if ( rval == (int)IpsOption::FAILED_BIT )
        {
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "failed bit\n");
            eval_data.flowbit_failed = 1;
            // clear the timestamp so failed flowbit gets eval'd again
            state.last_check.flowbit_failed = 1;
            state.last_check.result = result;
            return 0;
        }
        else if ( rval == (int)IpsOption::NO_ALERT )
        {
            // Cache the current flowbit_noalert flag, and set it
            // so nodes below this don't alert.
            tmp_noalert_flag = eval_data.flowbit_noalert;
            eval_data.flowbit_noalert = 1;
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "flowbit no alert\n");
        }

#ifdef DEBUG_MSGS
        if ( trace_enabled(detection_trace, TRACE_RULE_VARS) )
        {
            char var_buf[100];
            std::string rule_vars;
            rule_vars.reserve(sizeof(var_buf));
            uint32_t dbg_extract_vars[]{0,0};
            for ( unsigned i = 0; i < NUM_IPS_OPTIONS_VARS; ++i )
            {
                GetVarValueByIndex(&(dbg_extract_vars[i]), (int8_t)i);
                safe_snprintf(var_buf, sizeof(var_buf), "var[%u]=0x%X ", i, dbg_extract_vars[i]);
                rule_vars.append(var_buf);
            }
            debug_logf(detection_trace, TRACE_RULE_VARS, p, "Rule options variables: %s\n",
                rule_vars.c_str());
        }
#endif

        if ( PacketLatency::fastpath() )
        {
            profile.stop(result != (int)IpsOption::NO_MATCH);
            state.last_check.result = result;
            return result;
        }

        {
            // Passed, check the children.
            if ( node->num_children )
            {
                // Back up byte_extract vars so they don't get overwritten between rules
                // If node has only 1 child - no need to back up on current step
                for ( unsigned i = 0; node->num_children > 1 && i < NUM_IPS_OPTIONS_VARS; ++i )
                    GetVarValueByIndex(&(tmp_byte_extract_vars[i]), (int8_t)i);

                for ( int i = 0; i < node->num_children; ++i )
                {
                    detection_option_tree_node_t* child_node = node->children[i];
                    dot_node_state_t* child_state = child_node->state + get_instance_id();

                    for ( unsigned j = 0; node->num_children > 1 && j < NUM_IPS_OPTIONS_VARS; ++j )
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
                                    IpsOption* opt = (IpsOption*)node->option_data;

                                    if ( !opt->is_buffer_setter() )
                                    {
                                        // Check for an unbounded relative search.  If this
                                        // failed before, it's going to fail again so don't
                                        // go down this path again
                                        opt = (IpsOption*)child_node->option_data;
                                        PatternMatchData* pmd = opt->get_pattern(0, RULE_WO_DIR);

                                        if ( pmd and pmd->is_literal() and pmd->is_unbounded() )
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

                    eval_data.buf_selector = buf_selector;
                    child_state->result = detection_option_node_evaluate(
                        node->children[i], eval_data, cursor);

                    if ( child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
                    {
                        // Leaf node won't have any children but will return success
                        // or failure; regardless we must count them here
                        result += 1;
                    }
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
                // distance/within adjustments for this same content/pcre rule option.
                // If the node and its sub-tree propagate MATCH back,
                // then all its continuations are recalled.
                if ( result == node->num_children )
                {
                    continue_loop = false;
                    Continuation::recall(state, p);
                }

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
            eval_data.flowbit_noalert = tmp_noalert_flag;
        }

        if ( continue_loop && rval == (int)IpsOption::MATCH && node->relative_children )
        {
            IpsOption* opt = (IpsOption*)node->option_data;
            continue_loop = opt->retry(cursor, orig_cursor);
        }
        else
            continue_loop = false;

        // We're essentially checking this node again and it potentially
        // might match again
        if ( continue_loop )
        {
            state.checks++;
            node_eval_trace(node, cursor, eval_data.p);
        }
        loop_count++;
    }
    while ( continue_loop );

    if ( eval_data.flowbit_failed )
    {
        // something deeper in the tree failed a flowbit test, we may need to
        // reeval this node
        state.last_check.flowbit_failed = 1;
    }

    state.last_check.result = result;
    profile.stop(result != (int)IpsOption::NO_MATCH);

    return result;
}

static void detection_option_node_update_otn_stats(detection_option_tree_node_t* node,
    const dot_node_state_t* stats, unsigned thread_id, std::unordered_map<SigInfo*, OtnState>& entries)
{
    dot_node_state_t local_stats(node->state[thread_id]); /* cumulative stats for this node */

    if (stats)
    {
        local_stats.elapsed += stats->elapsed;
        local_stats.elapsed_match += stats->elapsed_match;
        local_stats.elapsed_no_match += stats->elapsed_no_match;

        if (stats->checks > local_stats.checks)
            local_stats.checks = stats->checks;

        local_stats.latency_suspends += stats->latency_suspends;
        local_stats.latency_timeouts += stats->latency_timeouts;
    }

    if ( node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
    {
        // Update stats for this otn
        auto* otn = (OptTreeNode*)node->option_data;
        auto& state = otn->state[thread_id];

        state.elapsed = local_stats.elapsed;
        state.elapsed_match = local_stats.elapsed_match;
        state.elapsed_no_match = local_stats.elapsed_no_match;

        if (local_stats.checks > state.checks)
            state.checks = local_stats.checks;

        state.latency_timeouts = local_stats.latency_timeouts;
        state.latency_suspends = local_stats.latency_suspends;

        static std::mutex rule_prof_stats_mutex;
        std::lock_guard<std::mutex> lock(rule_prof_stats_mutex);

        // All threads totals
        OtnState& totals = entries[&otn->sigInfo];

        totals.elapsed += state.elapsed;
        totals.elapsed_match += state.elapsed_match;
        totals.elapsed_no_match += state.elapsed_no_match;
        totals.checks += state.checks;
        totals.latency_timeouts += state.latency_timeouts;
        totals.latency_suspends += state.latency_suspends;
        totals.matches += state.matches;
        totals.alerts += state.alerts;
    }

    if ( node->num_children )
    {
        for ( int i = 0; i < node->num_children; ++i )
            detection_option_node_update_otn_stats(node->children[i], &local_stats, thread_id, entries);
    }
}

static void detection_option_node_reset_otn_stats(detection_option_tree_node_t* node,
    unsigned thread_id)
{
    node->state[thread_id].reset_profiling();

    if ( node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
    {
        auto& state = ((OptTreeNode*)node->option_data)->state[thread_id];
        state = OtnState();
    }

    if ( node->num_children )
    {
        for ( int i = 0; i < node->num_children; ++i )
            detection_option_node_reset_otn_stats(node->children[i], thread_id);
    }
}

void detection_option_tree_update_otn_stats(std::vector<HashNode*>& nodes, std::unordered_map<SigInfo*, OtnState>& stats, unsigned thread_id)
{
    for ( auto hnode : nodes )
    {
        auto* node = (detection_option_tree_node_t*)hnode->data;
        assert(node);

        if ( node->state[thread_id].checks )
            detection_option_node_update_otn_stats(node, nullptr, thread_id, stats);
    }
}

void detection_option_tree_reset_otn_stats(std::vector<HashNode*>& nodes, unsigned thread_id)
{
    for ( auto hnode : nodes )
    {
        auto* node = (detection_option_tree_node_t*)hnode->data;
        assert(node);

        if ( node->state[thread_id].checks )
            detection_option_node_reset_otn_stats(node, thread_id);
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
