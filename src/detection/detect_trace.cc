//--------------------------------------------------------------------------
// Copyright (C) 2017-2017 Cisco and/or its affiliates. All rights reserved.
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

// detect_trace.cc author Maya Dagon <mdagon@cisco.com>

#include "detect_trace.h"

#include <cctype>
#include <string>

#include "log/log.h"
#include "main/snort_debug.h"
#include "main/thread.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "packet_io/active.h"

#include "fp_create.h"
#include "treenodes.h"

using namespace std;

Trace TRACE_NAME(detection);

#ifdef DEBUG_MSGS

const uint64_t trace_buffer = TRACE_BUFFER_MINIMAL | TRACE_BUFFER_VERBOSE;

static THREAD_LOCAL char* cursor_name = nullptr;
static THREAD_LOCAL unsigned cursor_pos = -1;
static THREAD_LOCAL Packet* pkt = nullptr;

void clear_trace_cursor_info()
{
    if (cursor_name != nullptr)
    {
        snort_free(cursor_name);
        cursor_name = nullptr;
    }
    cursor_pos = -1;
}

void print_pkt_info(Packet* p)
{
    const char* dir;
    string dst_addr, src_addr;
    unsigned src_port = 0, dst_port = 0;

    pkt = p; //save packet pointer for later

    if ( pkt->is_from_client() )
        dir = "C2S";
    else if ( pkt->is_from_server() )
        dir = "S2C";
    else
        dir = "UNK";

    if ( pkt->has_ip() or pkt->is_data() )
    {
        src_addr = string(pkt->ptrs.ip_api.get_src()->ntoa());
        dst_addr = string(pkt->ptrs.ip_api.get_dst()->ntoa());
    }

    if ( pkt->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        src_port = pkt->ptrs.sp;
        dst_port = pkt->ptrs.dp;
    }

    trace_logf(detection, TRACE_RULE_EVAL,"packet %" PRIu64 " %s %s:%u %s:%u\n",
        pc.total_from_daq, dir, src_addr.c_str(), src_port, dst_addr.c_str(), dst_port);
}

void print_pattern(const PatternMatchData* pmd)
{
    string hex, txt, opts;

    get_pattern_info(pmd, pmd->pattern_buf, pmd->pattern_size, hex, txt, opts);
    trace_logf(detection, TRACE_RULE_EVAL,
        "Fast pattern %s[%u] = '%s' |%s| %s\n",
        pm_type_strings[pmd->pm_type],  pmd->pattern_size,
        txt.c_str(), hex.c_str(), opts.c_str());
}

void dump_buffer(const uint8_t* buff, unsigned len)
{
    if (!trace_enabled(detection_trace, trace_buffer))
        return;

    if (len == 0)
    {
        trace_log(detection, "Buffer dump - empty buffer\n");
        return;
    }

    assert (pkt != nullptr);
    LogNetData(buff, len, pkt);
}

void node_eval_trace(const detection_option_tree_node_t* node, const Cursor& cursor)
{
    const char* name = cursor.get_name();
    unsigned pos = cursor.get_pos();

    if (node->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        trace_logf(detection, TRACE_RULE_EVAL,
            "Evaluating option %s, cursor name %s, cursor position %u\n",
            ((IpsOption*)node->option_data)->get_name(), name, pos);
    }
    else
    {
        trace_logf(detection, TRACE_RULE_EVAL, "Reached leaf, cursor name %s, cursor position %u\n",
				  name, pos);
    }

    if (!trace_enabled(detection_trace, trace_buffer))
        return;

    if (trace_enabled(detection_trace, TRACE_BUFFER_VERBOSE))
    {
        dump_buffer(cursor.buffer() + pos, cursor.length());
    }
    else if ((pos != cursor_pos) || strcmp(cursor_name, name))
    {
        cursor_pos = pos;
        snort_free(cursor_name);
        cursor_name = snort_strdup(name);
        dump_buffer(cursor.buffer() + pos, cursor.length());
    }
}

#else

void clear_trace_cursor_info()
{
}

void print_pkt_info(Packet*)
{
}

void print_pattern(const PatternMatchData*)
{
}

void dump_buffer(const uint8_t*, unsigned)
{
}

void node_eval_trace(const detection_option_tree_node_t*, const Cursor&)
{
}

#endif

