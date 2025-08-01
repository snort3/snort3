//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// detection_options.cc author Steve Sturges <ssturges@cisco.com>
// detection_options.cc author Yehor Velykozhon <yvelykoz@cisco.com>

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
#include "ips_options/ips_flowbits.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency_state.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/ips_manager.h"
#include "parser/parser.h"
#include "profiler/rule_profiler_defs.h"
#include "protocols/packet_manager.h"
#include "time/packet_time.h"
#include "utils/util_cstring.h"

#include "detection_continuation.h"
#include "detection_engine.h"
#include "detection_module.h"
#include "detect_trace.h"
#include "extract.h"
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

        assert(key1 and key2);

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
#if (defined(__ia64) or defined(__amd64) or defined(_LP64))
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
        assert(k1 and k2);

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
        delete (detection_option_tree_node_t*)hnode->data;
    }

};

static DetectionOptionHash* allocate_option_hash_table()
{
   return new DetectionOptionHash(HASH_RULE_OPTIONS, sizeof(detection_option_key_t));
}

static DetectionOptionTreeHash* allocate_tree_hash_table()
{
    return new DetectionOptionTreeHash(HASH_RULE_TREE, sizeof(detection_option_key_t));
}

void* add_detection_option(SnortConfig* sc, option_type_t type, void* option_data)
{
    if ( !sc->detection_option_hash_table )
        sc->detection_option_hash_table = allocate_option_hash_table();

    detection_option_key_t key;
    key.option_type = type;
    key.option_data = option_data;

    if ( void* p = sc->detection_option_hash_table->get_user_data(&key) )
        return p;

    sc->detection_option_hash_table->insert(&key, option_data);
    return nullptr;
}

void* add_detection_option_tree(SnortConfig* sc, detection_option_tree_node_t* option_tree)
{
    static std::mutex build_mutex;
    std::lock_guard<std::mutex> lock(build_mutex);

    if ( !sc->detection_option_tree_hash_table )
        sc->detection_option_tree_hash_table = allocate_tree_hash_table();

    detection_option_key_t key;
    key.option_data = (void*)option_tree;
    key.option_type = RULE_OPTION_TYPE_LEAF_NODE;

    if ( void* p = sc->detection_option_tree_hash_table->get_user_data(&key) )
        return p;

    sc->detection_option_tree_hash_table->insert(&key, option_tree);
    return nullptr;
}

static inline bool was_evaluated(const detection_option_tree_node_t* node,
    const dot_node_state_t& state, uint64_t cur_eval_context_num, const Packet* p)
{
    // FIXIT-P: re-order for non-pcap traffic + add attributes
    if ( node->is_relative )
        return false;

    // FIXIT-L: once good order is determined, move to dot_node_state_t::operator==
    auto last_check = state.last_check;

    if ( last_check.ts.tv_sec != p->pkth->ts.tv_sec or
        last_check.ts.tv_usec != p->pkth->ts.tv_usec )
        return false;

    if ( last_check.run_num != get_run_num() )
        return false;

    if ( last_check.context_num != cur_eval_context_num )
        return false;

    if ( last_check.rebuild_flag != (p->packet_flags & PKT_REBUILT_STREAM) )
        return false;

    if (p->packet_flags & PKT_ALLOW_MULTIPLE_DETECT)
        return false;

    if ( last_check.flowbit_failed )
        return false;

    if ( !(p->packet_flags & PKT_IP_RULE_2ND) and !p->is_udp_tunneled() )
    {
        debug_log(detection_trace, TRACE_RULE_EVAL, p,
            "Was evaluated before, returning last check result\n");
        return true;
    }

    return false;
}

static inline bool match_rtn(const detection_option_tree_node_t* node, Packet* p)
{
    assert(p and node);
    // FIXIT-L: all those checks could be moved to OptTreeNode
    if ( !node->otn or node->otn->sigInfo.file_id )
        return true;

    const SnortProtocolId snort_protocol_id = p->get_snort_protocol_id();
    // FIXIT-L: rework to use bool
    int check_ports = 1;

    if ( snort_protocol_id != UNKNOWN_PROTOCOL_ID )
    {
        const auto& sig_info = node->otn->sigInfo;

        if ( std::any_of(sig_info.services.cbegin(), sig_info.services.cend(),
            [snort_protocol_id] (const SignatureServiceInfo& svc)
            { return snort_protocol_id == svc.snort_protocol_id; }) )
            check_ports = 0;

        if ( !sig_info.services.empty() and check_ports )
        {
            debug_logf(detection_trace, TRACE_RULE_EVAL, p,
                "SID %u not matched because of service mismatch %d\n",
                sig_info.sid, snort_protocol_id);
            return false;
        }
    }

    return fp_eval_rtn(getRtnFromOtn(node->otn), p, check_ports);
}

static inline int match_leaf(const detection_option_tree_node_t* node,
    detection_option_eval_data_t& eval_data)
{
    const Packet* p = eval_data.p;
    OptTreeNode* otn = (OptTreeNode*)node->option_data;

    if ( otn->detection_filter )
    {
        debug_log(detection_trace, TRACE_RULE_EVAL, p,
            "Evaluating detection filter\n");

        if ( detection_filter_test(otn->detection_filter, p) )
        {
            debug_log(detection_trace, TRACE_RULE_EVAL, p,
                "Header check failed\n");

            return (int)IpsOption::NO_MATCH;
        }
    }

    otn->state[get_instance_id()].matches++;

    eval_data.leaf_reached = 1;

    if ( eval_data.flowbit_noalert )
        return (int)IpsOption::MATCH;

#ifdef DEBUG_MSGS
    const SigInfo& si = otn->sigInfo;
    debug_logf(detection_trace, TRACE_RULE_EVAL, p,
        "Matched rule gid:sid:rev %u:%u:%u\n", si.gid, si.sid, si.rev);
#endif

    fpAddMatch(p->context->otnx, otn);

    return (int)IpsOption::MATCH;
}

static inline int match_flowbit(const detection_option_tree_node_t* node,
    detection_option_eval_data_t& eval_data, Cursor& cursor)
{
    int rval = node->evaluate(node->option_data, cursor, eval_data.p);

    assert((flowbits_setter(node->option_data) and rval == (int)IpsOption::MATCH)
        or !flowbits_setter(node->option_data) or !eval_data.p->flow);

    return rval;
}

static inline int match_node(const detection_option_tree_node_t* node,
    detection_option_eval_data_t& eval_data, Cursor& cursor,
    IpsOption*& buf_selector)
{
    IpsOption* opt = (IpsOption*)node->option_data;
    if ( opt->is_buffer_setter() )
        buf_selector = opt;

    int rval = node->evaluate(node->option_data, cursor, eval_data.p);

    return rval;
}

static inline bool skip_on_retry(const detection_option_tree_node_t* node,
    const detection_option_tree_node_t* child_node, dot_node_state_t* child_state,
    int loop_count, int& result)
{
    assert(loop_count > 0);
    assert(child_state);

    if ( child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
        return true;

    bool matched_all_suboption = child_state->result == child_node->num_children;
    if ( matched_all_suboption )
        return true;

    if ( child_node->option_type != RULE_OPTION_TYPE_CONTENT )
        return false;

    if ( child_state->result != (int)IpsOption::NO_MATCH )
        return false;

    if ( !child_node->is_relative )
    {
        // If it's a non-relative content or pcre, no reason
        // to check again.  Only increment result once.
        // Should hit this condition on first loop iteration.
        if ( loop_count == 1 )
            ++result;
        return true;
    }

    IpsOption* opt = (IpsOption*)node->option_data;
    if ( opt->is_buffer_setter() )
        return false;

    // FIXIT-L: should be moved to IpsOption option
    // Check for an unbounded relative search.  If this
    // failed before, it's going to fail again so don't
    // go down this path again
    opt = (IpsOption*)child_node->option_data;
    PatternMatchData* pmd = opt->get_pattern(0, RULE_WO_DIR);

    if ( pmd and pmd->is_literal() and pmd->is_unbounded() and !pmd->is_negated() )
    {
        // Only increment result once. Should hit this
        // condition on first loop iteration
        if ( loop_count == 1 )
            ++result;

        return true;
    }

    return false;
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

    if ( was_evaluated(node, state, cur_eval_context_num, eval_data.p) )
        return state.last_check.result;

    state.last_check.set(*eval_data.p, state.last_check.result);
    assert(state.last_check.context_num == eval_data.p->context->context_num);

    bool continue_loop = true;
    int loop_count = 0;

    int result = 0;
    uint32_t tmp_byte_extract_vars[NUM_IPS_OPTIONS_VARS];
    IpsOption* buf_selector = eval_data.buf_selector;
    Cursor cursor = orig_cursor;

    do
    {
        int rval = (int)IpsOption::NO_MATCH;  // FIXIT-L refactor to eliminate casts to int.

        if ( !match_rtn(node, p) )
            break;

        switch ( node->option_type )
        {
        case RULE_OPTION_TYPE_LEAF_NODE:
            result = rval = match_leaf(node, eval_data);
            break;

        case RULE_OPTION_TYPE_FLOWBIT:
            rval = match_flowbit(node, eval_data, cursor);
            break;

        default:
            rval = match_node(node, eval_data, cursor, buf_selector);
            break;
        }

        if ( rval == (int)IpsOption::NO_MATCH )
        {
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "no match\n");
            state.last_check.result = result;
            // See if the option has failed due to incomplete input or its failed evaluation
            if ( orig_cursor.awaiting_data() )
                Continuation::postpone<false>(orig_cursor, *node, eval_data);
            else
                Continuation::postpone<true>(cursor, *node, eval_data);

            return result;
        }
        if ( rval == (int)IpsOption::FAILED_BIT )
        {
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "failed bit\n");
            eval_data.flowbit_failed = 1;
            // clear the timestamp so failed flowbit gets eval'd again
            state.last_check.flowbit_failed = 1;
            state.last_check.result = result;

            return (int)IpsOption::NO_MATCH;
        }

        // Cache the current flowbit_noalert flag, and set it
        // so nodes below this don't alert.
        char tmp_noalert_flag = eval_data.flowbit_noalert;
        if ( rval == (int)IpsOption::NO_ALERT )
        {
            eval_data.flowbit_noalert = 1;
            debug_log(detection_trace, TRACE_RULE_EVAL, p, "flowbit no alert\n");
        }

        ips_variables_trace(p);

        if ( PacketLatency::fastpath() )
        {
            // Reset the flowbit_noalert flag in eval data
            eval_data.flowbit_noalert = tmp_noalert_flag;
            profile.stop(result != (int)IpsOption::NO_MATCH);
            state.last_check.result = result;
            return result;
        }

        // Passed, check the children.
        if ( node->num_children )
        {
            // Back up byte_extract vars so they don't get overwritten between rules
            // If node has only 1 child - no need to back up on current step
            for ( unsigned i = 0; node->num_children > 1 and i < NUM_IPS_OPTIONS_VARS; ++i )
                    GetVarValueByIndex(&(tmp_byte_extract_vars[i]), (int8_t)i);

            for ( int i = 0; i < node->num_children; ++i )
            {
                detection_option_tree_node_t* child_node = node->children[i];
                dot_node_state_t* child_state = child_node->state + get_instance_id();

                for ( unsigned j = 0; node->num_children > 1 and j < NUM_IPS_OPTIONS_VARS; ++j )
                    SetVarValueByIndex(tmp_byte_extract_vars[j], (int8_t)j);

                if ( loop_count > 0 and skip_on_retry(node, child_node, child_state, loop_count, result) )
                    continue;

                eval_data.buf_selector = buf_selector;
                child_state->result = detection_option_node_evaluate(node->children[i], eval_data, cursor);

                if ( child_node->option_type == RULE_OPTION_TYPE_LEAF_NODE )
                {
                    // Leaf node won't have any children but will return success
                    // or failure; regardless we must count them here
                    result += 1;
                }
                else if ( child_state->result == child_node->num_children )
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

            if ( eval_data.leaf_reached and !eval_data.otn->sigInfo.file_id and
                node->option_type != RULE_OPTION_TYPE_LEAF_NODE and
                ((IpsOption*)node->option_data)->is_buffer_setter() )
            {
                debug_logf(detection_trace, TRACE_BUFFER, p, "Collecting \"%s\" buffer of size %u\n",
                    cursor.get_name(), cursor.size());
                p->context->matched_buffers.emplace_back(cursor.get_name(), cursor.buffer(), cursor.size());
                pc.buf_dumps++;
            }
        }

        // Reset the flowbit_noalert flag in eval data
        eval_data.flowbit_noalert = tmp_noalert_flag;

        if ( continue_loop and rval == (int)IpsOption::MATCH and node->relative_children )
        {
            IpsOption* opt = (IpsOption*)node->option_data;
            continue_loop = opt->retry(cursor);
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

    if ( stats )
    {
        local_stats.elapsed += stats->elapsed;
        local_stats.elapsed_match += stats->elapsed_match;
        local_stats.elapsed_no_match += stats->elapsed_no_match;

        if ( stats->checks > local_stats.checks )
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

        if ( local_stats.checks > state.checks )
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

        detection_option_node_reset_otn_stats(node, thread_id);
    }
}

void free_detection_option_root(void** existing_tree)
{
    detection_option_tree_root_t* root;

    if ( !existing_tree or !*existing_tree )
        return;

    root = (detection_option_tree_root_t*)*existing_tree;
    snort_free(root->children);

    delete root;
    *existing_tree = nullptr;
}


//-------------------------------------------------------------------------
// UNIT TESTS
//-------------------------------------------------------------------------

#ifdef UNIT_TEST

#include "catch/snort_catch.h"

#include "filters/sfthd.h"

static void set_was_evaluated(detection_option_tree_node_t& n, Packet* p,
    dot_node_state_t& s, uint64_t& c_num)
{
    n.is_relative = false;
    auto& last_check = s.last_check;

    if ( !p->pkth )
        p->pkth = new DAQ_PktHdr_t();

    last_check.ts = p->pkth->ts;
    last_check.run_num = get_run_num();
    last_check.context_num = c_num = 2;
    last_check.rebuild_flag = p->packet_flags = p->packet_flags | PKT_REBUILT_STREAM;
    last_check.flowbit_failed = false;
}

TEST_CASE("Detection Engine: was_evaluated", "[de_core]")
{
    Packet p;
    detection_option_tree_node_t m_node(RULE_OPTION_TYPE_OTHER, nullptr);
    dot_node_state_t m_state;
    uint64_t m_context_num;

    SECTION("Basic passed case")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        REQUIRE(true == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    SECTION("Failed due to relative option")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        m_node.is_relative = true;
        REQUIRE(false == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    SECTION("Failed due to timestamp difference")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        m_state.last_check.ts.tv_sec = 1;
        bool fail_due_last_check = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_last_check);

        set_was_evaluated(m_node, &p, m_state, m_context_num);
        const_cast<DAQ_PktHdr_t* >(p.pkth)->ts.tv_sec = 1;
        bool fail_due_packet = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_packet);
    }
    SECTION("Failed due to run number")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        m_state.last_check.run_num = 1;
        bool fail_due_last_check = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_last_check);

        set_was_evaluated(m_node, &p, m_state, m_context_num);
        int orig_run_num = get_run_num();
        set_run_num(1);
        bool fail_due_global_run_num = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_global_run_num);
        set_run_num(orig_run_num);
    }
    SECTION("Failed due to context number")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        m_state.last_check.context_num = 1;
        REQUIRE(false == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    SECTION("Failed due to not rebuilt stream packet")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        p.packet_flags = 0;
        REQUIRE(false == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    SECTION("Failed due to multiple detection")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        p.packet_flags |= PKT_ALLOW_MULTIPLE_DETECT;
        REQUIRE(false == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    SECTION("Failed due to failed flowbit in state.last_check")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        m_state.last_check.flowbit_failed = 1;
        REQUIRE(false == was_evaluated(&m_node, m_state, m_context_num, &p));
    }
    // FIXIT-L: what is the correct name of this condition? not inner tcp evaluation?
    SECTION("Failed due to ip layer and udp check")
    {
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        p.packet_flags = 0;
        bool fail_due_packet_flag = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_packet_flag);
        set_was_evaluated(m_node, &p, m_state, m_context_num);
        p.proto_bits |= PROTO_BIT__UDP_TUNNELED;
        p.ptrs.udph = (const snort::udp::UDPHdr*)0x1; // This is a hack to avoid irrelevant assert in "is_udp_tunneled"
        bool fail_due_udp_tunneled = false == was_evaluated(&m_node, m_state, m_context_num, &p);
        REQUIRE(fail_due_udp_tunneled);
    }
}

TEST_CASE("Detection Engine: match_rtn", "[de_core]")
{
    std::unique_ptr<OptTreeNode> otn(new OptTreeNode());
    detection_option_tree_node_t m_node(RULE_OPTION_TYPE_OTHER, nullptr);
    m_node.otn = otn.get();

    // Needed to pass protocol/service check
    std::unique_ptr<IpsContext> context(new IpsContext(1));
    context->set_snort_protocol_id(UNKNOWN_PROTOCOL_ID);
    context->packet->ptrs.type = PktType::PDU; // in order to get snort_protocol_id from IpsContext;
    Packet* p = context->packet;

    RuleTreeNode rtn;
    otn->proto_node_num = 1;
    // will be de-allocated in ~Otn
    otn->proto_nodes = (RuleTreeNode**)snort_calloc(1, sizeof(RuleTreeNode*));
    otn->proto_nodes[0] = &rtn;

    std::unique_ptr<IpsPolicy> ips_policy(new IpsPolicy());
    ips_policy->policy_id = 0;
    set_ips_policy(ips_policy.get());

    // Needed to pass fp_eval_rtn
    rtn.set_enabled();
    std::unique_ptr<RuleFpList> fp_list(new RuleFpList);
    rtn.rule_func = fp_list.get();

    SECTION("Passed due to middle-node evaluation")
    {
        detection_option_tree_node_t middle_node(RULE_OPTION_TYPE_OTHER, nullptr);
        bool non_rtn_containig_node = !middle_node.otn;

        REQUIRE(non_rtn_containig_node);
        REQUIRE(true == match_rtn(&middle_node, p));
    }
    SECTION("Passed due to file id rule")
    {
        bool rtn_containig_node = m_node.otn;
        REQUIRE(rtn_containig_node);

        const_cast<OptTreeNode*>(m_node.otn)->sigInfo.file_id = 1;
        REQUIRE(true == match_rtn(&m_node, p));
    }
    SECTION("Check protocol")
    {
        SECTION("Failed due to no known service")
        {
            context->set_snort_protocol_id(SNORT_PROTO_TCP);
            otn->sigInfo.services.push_back({"not-tcp", SNORT_PROTO_UDP});
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int) -> int
            { assert(false); return 1; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(false == match_rtn(&m_node, p));
        }
        SECTION("Match due to empty service list")
        {
            context->set_snort_protocol_id(SNORT_PROTO_TCP);
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int) -> int
            { return 1; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(true == match_rtn(&m_node, p));
        }
    }
    SECTION("Evaluation of fp_eval_rtn")
    {
        SECTION("RTN matched")
        {
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int) -> int { return 1; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(true == match_rtn(&m_node, p));
        }
        SECTION("RTN mismatched")
        {
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int) -> int { return 0; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(false == match_rtn(&m_node, p));
        }
        SECTION("Ports are checked in case of unknown protocol_id")
        {
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int check_ports) -> int
            { return check_ports; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(true == match_rtn(&m_node, p));
        }
        SECTION("RTN user_mode priority over service-check")
        {
            context->set_snort_protocol_id(SNORT_PROTO_TCP);
            otn->sigInfo.services.push_back({"tcp", SNORT_PROTO_TCP});
            rtn.flags |= RuleTreeNode::USER_MODE;
            auto mock_r_func = [](snort::Packet*, RuleTreeNode*, RuleFpList*, int check_ports) -> int
            { return check_ports; };
            rtn.rule_func->RuleHeadFunc = mock_r_func;

            REQUIRE(true == match_rtn(&m_node, p));
        }
    }
}

TEST_CASE("Detection Engine: match_leaf", "[de_core]")
{
    std::unique_ptr<OptTreeNode> otn(new OptTreeNode());
    detection_option_tree_node_t m_node(RULE_OPTION_TYPE_OTHER, otn.get());
    detection_option_eval_data_t m_e_data;
    Packet p;
    m_e_data.p = &p;
    otn->state = new OtnState[1]();
    set_instance_id(0);

    SECTION("Detection filter passed, state.matches increased")
    {
        // de-allocated in ~Otn
        otn->detection_filter = new THD_NODE();
        detection_filter_term();    // need to make early exit from detection_filter logic
        m_e_data.flowbit_noalert = true;   // Avoid extra work in such way
        uint64_t curr_matches = otn->state[get_instance_id()].matches;

        // Needed for detection_filter_test
        std::unique_ptr<IpsPolicy> ips_policy(new IpsPolicy());
        ips_policy->policy_id = 0;
        set_ips_policy(ips_policy.get());

        REQUIRE(match_leaf(&m_node, m_e_data));
        REQUIRE(curr_matches +1 == otn->state[get_instance_id()].matches);
    }
    SECTION("state.matches counter is increased")
    {
        uint64_t curr_matches = otn->state[get_instance_id()].matches;
        m_e_data.flowbit_noalert = true;   // Avoid extra work in such way

        REQUIRE(match_leaf(&m_node, m_e_data));
        REQUIRE(curr_matches +1 == otn->state[get_instance_id()].matches);
    }
    SECTION("leaf_reached flag is set")
    {
        char curr_flag = m_e_data.leaf_reached;
        m_e_data.flowbit_noalert = true;   // Avoid extra work in such way

        REQUIRE(match_leaf(&m_node, m_e_data));
        REQUIRE(curr_flag != m_e_data.leaf_reached);
        REQUIRE(m_e_data.leaf_reached);

        SECTION("Verify that flag is set, not toggled")
        {
            m_e_data.leaf_reached = 1;
            char reached = m_e_data.leaf_reached;
            m_e_data.flowbit_noalert = true;   // Avoid extra work in such way

            REQUIRE(match_leaf(&m_node, m_e_data));
            REQUIRE(reached == m_e_data.leaf_reached);
        }
    }
    SECTION("Alert the match")
    {
        std::unique_ptr<IpsContext> context(new IpsContext(1));
        context->set_snort_protocol_id(UNKNOWN_PROTOCOL_ID);
        m_e_data.p = context->packet;

        // Forcing underlying function return nullptr since the test target not the fpAddMatch function.
        // In such way, the fpAddMatch will return 2, which is still fine for us.
        otn->proto_node_num = 1;

        otn->proto_nodes = (RuleTreeNode**)snort_calloc(1, sizeof(RuleTreeNode*));
        otn->proto_nodes[0] = nullptr;

        std::unique_ptr<IpsPolicy> ips_policy(new IpsPolicy());
        ips_policy->policy_id = 0;
        set_ips_policy(ips_policy.get());

        REQUIRE(match_leaf(&m_node, m_e_data));
    }
}

class MockIpsBufSetter : public IpsOption
{
public:
    MockIpsBufSetter(const char* s) : IpsOption(s)
    { }

    CursorActionType get_cursor_type() const override
    { return CAT_SET_SUB_SECTION; }
};

class MockIpsOptRead : public IpsOption
{
public:
    MockIpsOptRead(const char* s) : IpsOption(s)
    { }

    CursorActionType get_cursor_type() const override
    { return CAT_READ; }
};

TEST_CASE("Detection Engine: match_node", "[de_core]")
{
    detection_option_eval_data_t m_e_data;
    Cursor m_c;
    detection_option_tree_node_t m_node(RULE_OPTION_TYPE_OTHER, nullptr);
    auto mock_eval = [](void*, class Cursor&, snort::Packet*) -> int { return 1; };
    m_node.evaluate = mock_eval;
    MockIpsBufSetter mock_ips_setter ("mock_ips_setter");
    MockIpsOptRead mock_ips_read ("mock_ips_read");

    SECTION("Buffer setter is set from option")
    {
        m_node.option_data = &mock_ips_setter;

        IpsOption* buf_selector = nullptr;
        REQUIRE(match_node(&m_node, m_e_data, m_c, buf_selector));
        REQUIRE(buf_selector == &mock_ips_setter);
    }
    SECTION("Empty buffer setter")
    {
        m_node.option_data = &mock_ips_read;

        IpsOption* buf_selector = nullptr;
        REQUIRE(match_node(&m_node, m_e_data, m_c, buf_selector));
        REQUIRE(buf_selector != &mock_ips_read);
        REQUIRE_FALSE(buf_selector);
    }
}

class MockIpsOptPMD : public IpsOption
{
public:
    MockIpsOptPMD(const char* s) : IpsOption(s)
    { pmd = new PatternMatchData(); }

    ~MockIpsOptPMD() override
    { delete pmd; }

    CursorActionType get_cursor_type() const override
    { return CAT_READ; }

    PatternMatchData* get_pattern(SnortProtocolId, RuleDirection) override
    { return pmd; }

private:
    PatternMatchData* pmd;
};

TEST_CASE("Detection Engine: skip_on_retry", "[de_core]")
{
    Packet p;
    detection_option_tree_node_t m_node(RULE_OPTION_TYPE_OTHER, nullptr);
    detection_option_tree_node_t m_child_node(RULE_OPTION_TYPE_OTHER, nullptr);
    detection_option_eval_data_t m_e_data;
    m_e_data.p = &p;
    dot_node_state_t m_child_state;
    int result = 0;

    SECTION("Skip child leaf node")
    {
        m_child_node.option_type = RULE_OPTION_TYPE_LEAF_NODE;
        REQUIRE(true == skip_on_retry(nullptr, &m_child_node, &m_child_state, 1, result));
        REQUIRE_FALSE(result);
    }
    SECTION("Skip if all following options are matched")
    {
        m_child_state.result = m_child_node.num_children = 0;
        REQUIRE(true == skip_on_retry(nullptr, &m_child_node, &m_child_state, 1, result));
    }

    SECTION("Do not skip all non-content nodes")
    {
        m_child_state.result = 1; // to avoid early exit
        REQUIRE(false == skip_on_retry(nullptr, &m_child_node, &m_child_state, 1, result));
    }
    SECTION("Retry of IPS content logic")
    {
        m_child_node.children = (detection_option_tree_node_t**)snort_calloc(2, sizeof(detection_option_tree_node_t*));
        m_child_node.num_children = 2; // to avoid early exit
        m_child_node.option_type = RULE_OPTION_TYPE_CONTENT;

        SECTION("Not skipping if matched previously")
        {
            m_child_state.result = 1;
            REQUIRE(false == skip_on_retry(nullptr, &m_child_node, &m_child_state, 1, result));
        }
        SECTION("Non-relative")
        {
            SECTION("Increase result on 1st loop")
            {
                int curr_result = result;
                m_child_node.is_relative = false;

                REQUIRE(true == skip_on_retry(nullptr, &m_child_node, &m_child_state, 1, result));
                REQUIRE(curr_result +1 == result);
            }
            SECTION("Do not affect result on non-1st loop")
            {
                int curr_result = result;
                m_child_node.is_relative = false;

                REQUIRE(true == skip_on_retry(nullptr, &m_child_node, &m_child_state, 2, result));
                REQUIRE(curr_result == result);
            }
        }

        m_child_node.is_relative = true;
        MockIpsBufSetter mock_ips_setter ("mock_ips_setter");
        MockIpsOptRead mock_ips_read ("mock_ips_read");
        MockIpsOptPMD mock_ips_pmd ("mock_ips_pmd");

        SECTION("Current Ips option is buffer setter")
        {

            m_node.option_data = &mock_ips_setter;

            REQUIRE(false == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
        }
        SECTION("Child node PMD evaluation")
        {
            m_node.option_data = &mock_ips_read;  // to avoid early exit

            m_child_node.option_data = &mock_ips_pmd;
            PatternMatchData* pmd = mock_ips_pmd.get_pattern(0, RULE_WO_DIR);

            SECTION("PMD for not exists")
            {
                m_child_node.option_data = &mock_ips_pmd;
                REQUIRE(false == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
            }
            SECTION("PMD not literal")
            {
                REQUIRE(false == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
            }
            SECTION("PMD not unbounded")
            {
                pmd->set_literal();
                pmd->depth = 1;
                REQUIRE(false == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
            }
            SECTION("PMD is negated")
            {
                pmd->set_literal();
                pmd->set_negated();
                REQUIRE(false == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
            }
            SECTION("Skipping on the 1st loop")
            {
                int curr_result = result;
                pmd->set_literal();

                REQUIRE(true == skip_on_retry(&m_node, &m_child_node, &m_child_state, 1, result));
                REQUIRE(curr_result +1 == result);
            }
            SECTION("Skipping on the non-1st loop")
            {
                int curr_result = result;
                pmd->set_literal();

                REQUIRE(true == skip_on_retry(&m_node, &m_child_node, &m_child_state, 2, result));
                REQUIRE(curr_result == result);
            }
        }
    }
}

#endif
