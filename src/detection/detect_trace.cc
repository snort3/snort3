//--------------------------------------------------------------------------
// Copyright (C) 2017-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detect_trace.h"

#include "log/log.h"
#include "protocols/packet.h"
#include "utils/stats.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "detection_options.h"
#include "extract.h"
#include "fp_create.h"
#include "fp_utils.h"
#include "ips_context.h"
#include "pattern_match_data.h"
#include "treenodes.h"

using namespace snort;
using namespace std;

#ifdef DEBUG_MSGS

static THREAD_LOCAL char* cursor_name = nullptr;
static THREAD_LOCAL unsigned cursor_pos = -1;

void clear_trace_cursor_info()
{
    if (cursor_name != nullptr)
    {
        snort_free(cursor_name);
        cursor_name = nullptr;
    }
    cursor_pos = -1;
}

void print_pkt_info(Packet* p, const char* task)
{
    const char* dir;
    SfIpString src_addr, dst_addr;
    unsigned src_port = 0, dst_port = 0;

    if ( p->is_from_application_client() )
        dir = "C2S";
    else if ( p->is_from_application_server() )
        dir = "S2C";
    else
        dir = "UNK";

    if ( p->has_ip() or p->is_data() )
    {
        p->ptrs.ip_api.get_src()->ntop(src_addr);
        p->ptrs.ip_api.get_dst()->ntop(dst_addr);
    }

    if ( p->proto_bits & (PROTO_BIT__TCP|PROTO_BIT__UDP) )
    {
        src_port = p->ptrs.sp;
        dst_port = p->ptrs.dp;
    }

    debug_logf(detection_trace, TRACE_RULE_EVAL, p,
        "packet %" PRIu64 " %s %s:%u %s:%u (%s)\n", p->context->packet_number,
        dir, src_addr, src_port, dst_addr, dst_port, task);
}

void print_pattern(const PatternMatchData* pmd, Packet* p)
{
    string hex, txt, opts;
    get_pattern_info(pmd, hex, txt, opts);

    debug_logf(detection_trace, TRACE_RULE_EVAL, p,
        "Fast pattern %s[%u] = %s %s %s\n",
        pmd->sticky_buf,  pmd->fp_length, txt.c_str(), hex.c_str(), opts.c_str());
}

void dump_buffer(const uint8_t* buff, unsigned len, Packet* p)
{
    if ( !trace_enabled(detection_trace, TRACE_BUFFER) )
        return;

    if (len == 0)
    {
        debug_log(detection_trace, TRACE_BUFFER, p,
            "Buffer dump - empty buffer\n");
        return;
    }

    LogNetData(buff, len, p);
}

void node_eval_trace(const detection_option_tree_node_t* node, const Cursor& cursor, Packet* p)
{
    const char* name = cursor.get_name();
    unsigned pos = cursor.get_pos();

    if (node->option_type != RULE_OPTION_TYPE_LEAF_NODE )
    {
        debug_logf(detection_trace, TRACE_RULE_EVAL, p,
            "Evaluating option %s, cursor name %s, cursor position %u\n",
            ((IpsOption*)node->option_data)->get_name(), name, pos);
    }
    else
    {
        debug_logf(detection_trace, TRACE_RULE_EVAL, p,
            "Reached leaf, cursor name %s, cursor position %u\n", name, pos);
    }

    if ( !trace_enabled(detection_trace, TRACE_BUFFER) )
        return;

    if ( trace_enabled(detection_trace, TRACE_BUFFER, 5) )
        dump_buffer(cursor.buffer() + pos, cursor.length(), p);
    else if ((pos != cursor_pos) || strcmp(cursor_name, name))
    {
        cursor_pos = pos;
        snort_free(cursor_name);
        cursor_name = snort_strdup(name);
        dump_buffer(cursor.buffer() + pos, cursor.length(), p);
    }
}

void ips_variables_trace(const Packet* const p)
{
    if ( !trace_enabled(detection_trace, TRACE_RULE_VARS) )
        return;

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

void print_option_tree(detection_option_tree_node_t* node, int level)
{
    if ( !trace_enabled(detection_trace, TRACE_OPTION_TREE) )
        return;

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
}

#else

void clear_trace_cursor_info() { }
void print_pkt_info(Packet*, const char*) { }
void print_pattern(const PatternMatchData*, Packet*) { }
void dump_buffer(const uint8_t*, unsigned, Packet*) { }
void node_eval_trace(const detection_option_tree_node_t*, const Cursor&, Packet*) { }
void ips_variables_trace(const Packet* const) { }
void print_option_tree(detection_option_tree_node_t*, int) { }

#endif
