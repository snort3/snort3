//--------------------------------------------------------------------------
// Copyright (C) 2022-2025 Cisco and/or its affiliates. All rights reserved.
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

// detection_continuation.h author Yehor Velykozhon <yvelykoz@cisco.com>

#ifndef DETECTION_CONTINUATION_H
#define DETECTION_CONTINUATION_H

#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "helpers/grouped_list.h"
#include "latency/rule_latency.h"
#include "latency/rule_latency_state.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "protocols/packet.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "detection_options.h"
#include "detect_trace.h"
#include "extract.h"
#include "ips_context.h"
#include "rule_option_types.h"
#include "treenodes.h"

class Continuation
{
public:
    template <bool opt_parent>
    static inline void postpone(const Cursor&,
        const detection_option_tree_node_t&, const detection_option_eval_data_t&);

    static inline void recall(dot_node_state_t&, const snort::Packet*);

    inline bool is_reloaded() const;

    inline void eval(snort::Packet&);

private:
    Continuation(unsigned max_cnt) : states_cnt(0), states_cnt_max(max_cnt),
        reload_id(snort::SnortConfig::get_thread_reload_id())
    { }

    template <bool opt_parent>
    inline void add(const Cursor&,
        const detection_option_tree_node_t&, const detection_option_eval_data_t&);

    struct State
    {
        State() : data(), root(), selector(nullptr), node(nullptr), waypoint(0),
            original_waypoint(0), delta(0), sid(0), packet_number(0), opt_parent(false), re_eval(false)
        {
            for (uint8_t i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
                byte_extract_vars[i] = 0;
        }

        State(const detection_option_tree_node_t& n, const detection_option_eval_data_t& d,
            snort::IpsOption* s, unsigned wp, unsigned dt, uint64_t id, bool p, bool r_e) : data(d),
            root(1, d.otn),
            selector(s), node(const_cast<detection_option_tree_node_t*>(&n)), waypoint(wp),
            original_waypoint(wp), delta(dt), sid(id), packet_number(d.p->context->packet_number),
            opt_parent(p), re_eval(r_e)
        {
            for (uint8_t i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
                snort::GetVarValueByIndex(&byte_extract_vars[i], i);

            root.children = &node;
        }

        inline bool eval(snort::Packet&);

        detection_option_eval_data_t data;
        detection_option_tree_root_t root;
        snort::IpsOption* selector;
        detection_option_tree_node_t* node;
        unsigned waypoint;
        const unsigned original_waypoint;
        unsigned delta;
        uint64_t sid;
        uint64_t packet_number;
        uint32_t byte_extract_vars[NUM_IPS_OPTIONS_VARS];
        bool opt_parent;
        bool re_eval;
    };

    using LState = snort::GroupedList<State>;

    LState states;
    unsigned states_cnt;
    const unsigned states_cnt_max;
    const unsigned reload_id;
};

template <bool opt_parent>
void Continuation::postpone(const Cursor& cursor,
    const detection_option_tree_node_t& node, const detection_option_eval_data_t& data)
{
    if (!cursor.awaiting_data())
        return;

    if (!data.p->has_paf_payload())
        return;

    assert(data.p->flow);

    auto cont = data.p->flow->ips_cont;

    if (!cont)
    {
        auto max_cnt = snort::SnortConfig::get_conf()->max_continuations;

        if (!max_cnt)
            return;

        cont = data.p->flow->ips_cont = new Continuation(max_cnt);
        snort::pc.cont_flows++;
    }

    cont->add<opt_parent>(cursor, node, data);
}

void Continuation::recall(dot_node_state_t& nst,
     const snort::Packet* p)
{
    if (nst.last_check.context_num != nst.context_num or
        nst.last_check.run_num != nst.run_num)
        return;

    auto cnt = LState::erase_group((LState*&)nst.conts);
    assert(nst.conts == nullptr);
    assert(cnt);

    debug_logf(detection_trace, TRACE_CONT, nullptr,
        "The path matched, dropping %u continuation(s)\n", cnt);

    assert(p);
    assert(p->flow);
    assert(p->flow->ips_cont);

    auto cont = p->flow->ips_cont;

    assert(cnt <= cont->states_cnt);
    cont->states_cnt -= cnt;
    snort::pc.cont_recalls += cnt;
}

bool Continuation::is_reloaded() const
{
    return snort::SnortConfig::get_thread_reload_id() != reload_id;
}

void Continuation::eval(snort::Packet& p)
{
    if (!p.has_paf_payload())
        return;

    debug_logf(detection_trace, TRACE_CONT, nullptr,
        "Processing %u continuation(s)\n", states_cnt);

    if (states_cnt > snort::pc.cont_max_num)
        snort::pc.cont_max_num = states_cnt;

    auto i = states.get_next();

    while (i != &states)
    {
        auto st = i;
        bool r = (**st).eval(p);
        i = st->get_next();

        if (r)
        {
            assert(0 < states_cnt);
            assert(st != &states);
            assert((**st).packet_number != p.context->packet_number);

            --states_cnt;
            delete st;
        }
    }
}

bool Continuation::State::eval(snort::Packet& p)
{
    Cursor cursor(&p);

    // Create local object to follow latency workflow
    RuleLatency::Context rule_latency_ctx(root, &p);

    if (RuleLatency::suspended())
        return true;

    if (packet_number == p.context->packet_number)
        return false;

    if (selector)
        selector->eval(cursor, &p);

    if (sid != cursor.id())
        return false;

    if (cursor.is_buffer_accumulated())
    {
        debug_logf(detection_trace, TRACE_CONT, nullptr,
            "Continuation dropped due to accumulated data in '%s'\n", cursor.get_name());

        return true;
    }

    cursor.set_pos(waypoint);
    cursor.set_delta(delta);

    if (cursor.awaiting_data(true) or cursor.size() == 0)
    {
        waypoint = cursor.get_next_pos();
        debug_logf(detection_trace, TRACE_CONT, &p,
            "Continuation postponed, %u bytes to go\n", waypoint);
        return false;
    }

    assert(cursor.get_name());
    debug_logf(detection_trace, TRACE_CONT, &p,
        "Cursor reached the position, evaluating sub-tree with "
        "current buffer '%s'\n", cursor.get_name());

    data.pmd = nullptr;
    data.p = &p;

    int result = 0;
    snort::pc.cont_evals++;

    for (uint8_t i = 0; i < NUM_IPS_OPTIONS_VARS; ++i)
        snort::SetVarValueByIndex(byte_extract_vars[i], i);

    const detection_option_tree_node_t* root_node = root.children[0];

    cursor.set_re_eval(re_eval);

    if (!opt_parent)
    {
        assert(!re_eval);
        result = detection_option_node_evaluate(root_node, data, cursor);
    }
    else if (re_eval)
    {
        result = detection_option_node_evaluate(root_node, data, cursor);
        root_node->state[snort::get_instance_id()].last_check.ts = {};
    }
    else
    {
        for (int i = 0; i < root_node->num_children; ++i)
            result += detection_option_node_evaluate(root_node->children[i], data, cursor);
    }

    if (data.leaf_reached and !data.otn->sigInfo.file_id)
    {
        data.p->context->matched_buffers.emplace_back(cursor.get_name(), cursor.buffer(), cursor.size());
        debug_logf(detection_trace, TRACE_BUFFER, data.p, "Collecting \"%s\" buffer of size %u on continuation root\n",
            cursor.get_name(), cursor.size());
        snort::pc.buf_dumps++;
    }

    clear_trace_cursor_info();

    if (result)
    {
        snort::pc.cont_matches++;
        snort::pc.cont_match_distance += original_waypoint;
    }
    else
    {
        snort::pc.cont_mismatches++;
        snort::pc.cont_mismatch_distance += original_waypoint;
    }

    return true;
}

template <bool opt_parent>
void Continuation::add(const Cursor& cursor,
    const detection_option_tree_node_t& node, const detection_option_eval_data_t& data)
{
    auto selector = data.buf_selector;
    auto pos = cursor.get_next_pos();
    auto sid = cursor.id();
    auto delta = cursor.get_delta();
    auto nst = node.state + snort::get_instance_id();
    assert(nst);

    if (nst->last_check.context_num != nst->context_num or
        nst->last_check.run_num != nst->run_num)
    {
        nst->context_num = nst->last_check.context_num;
        nst->run_num = nst->last_check.run_num;
        nst->conts = nullptr;
    }

    if (states_cnt < states_cnt_max)
    {
        ++states_cnt;
        new LState(states, (LState*&)nst->conts, node, data, selector, pos, delta, sid, opt_parent, cursor.is_re_eval());
    }
    else
    {
        debug_logf(detection_trace, TRACE_CONT, data.p,
            "Max size reached (%u), rejecting the oldest continuation\n",
            states_cnt_max);

        auto st = states.get_next();
        assert(st != &states);

        if ((**st).packet_number == data.p->context->packet_number)
            st->leave_group();
        delete st;

        new LState(states, (LState*&)nst->conts, node, data, selector, pos, delta, sid, opt_parent, cursor.is_re_eval());
    }

    snort::pc.cont_creations++;

    assert(cursor.get_name());
    assert(!selector || selector->get_name());
    debug_logf(detection_trace, TRACE_CONT, data.p,
        "Adding a continuation: "
        "current buffer '%s', buffer selector '%s'; %u more bytes needed\n",
        cursor.get_name(), selector ? selector->get_name() : "N/A", pos);
}

#endif
