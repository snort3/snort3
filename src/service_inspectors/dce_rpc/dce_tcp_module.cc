//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// dce_tcp_module.cc author Rashmi Pitre <rrp@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_tcp_module.h"

#include "log/messages.h"

#include "dce_tcp.h"

using namespace std;

static const Parameter s_params[] =
{
    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      " Disable DCE/RPC defragmentation" },
    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      " Maximum fragment size for defragmentation" },
    { "reassemble_threshold", Parameter::PT_INT, "0:65535", "0",
      " Minimum bytes received before performing reassembly" },
    { "policy", Parameter::PT_ENUM,
      "Win2000 |  WinXP | WinVista | Win2003 | Win2008 | Win7 | "
      "Samba | Samba-3.0.37 | Samba-3.0.22 | Samba-3.0.20", "WinXP",
      " Target based policy to use" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dce2_tcp_rules[] =
{
    { DCE2_CO_BAD_MAJOR_VERSION, DCE2_CO_BAD_MAJOR_VERSION_STR },
    { DCE2_CO_BAD_MINOR_VERSION, DCE2_CO_BAD_MINOR_VERSION_STR },
    { DCE2_CO_BAD_PDU_TYPE, DCE2_CO_BAD_PDU_TYPE_STR },
    { DCE2_CO_FRAG_LEN_LT_HDR, DCE2_CO_FRAG_LEN_LT_HDR_STR },
    { DCE2_CO_NO_CTX_ITEMS_SPECFD, DCE2_CO_NO_CTX_ITEMS_SPECFD_STR },
    { DCE2_CO_NO_TFER_SYNTAX_SPECFD, DCE2_CO_NO_TFER_SYNTAX_SPECFD_STR },
    { DCE2_CO_FRAG_LT_MAX_XMIT_FRAG, DCE2_CO_FRAG_LT_MAX_XMIT_FRAG_STR },
    { DCE2_CO_FRAG_GT_MAX_XMIT_FRAG, DCE2_CO_FRAG_GT_MAX_XMIT_FRAG_STR },
    { DCE2_CO_ALTER_CHANGE_BYTE_ORDER, DCE2_CO_ALTER_CHANGE_BYTE_ORDER_STR },
    { DCE2_CO_FRAG_DIFF_CALL_ID, DCE2_CO_FRAG_DIFF_CALL_ID_STR },
    { DCE2_CO_FRAG_DIFF_OPNUM, DCE2_CO_FRAG_DIFF_OPNUM_STR },
    { DCE2_CO_FRAG_DIFF_CTX_ID, DCE2_CO_FRAG_DIFF_CTX_ID_STR },
    { 0, nullptr }
};

static const PegInfo dce2_tcp_pegs[] =
{
    { "events", "total events" },
    { "pdus", "total connection-oriented PDUs" },
    { "binds", "total connection-oriented binds" },
    { "bind_acks", "total connection-oriented binds acks" },
    { "alter_contexts", "total connection-oriented alter contexts" },
    { "alter_context_responses", "total connection-oriented alter context responses" },
    { "bind_naks", "total connection-oriented bind naks" },
    { "requests", "total connection-oriented requests" },
    { "responses", "total connection-oriented responses" },
    { "cancels", "total connection-oriented cancels" },
    { "orphaned", "total connection-oriented orphaned" },
    { "faults", "total connection-oriented faults" },
    { "auth3s", "total connection-oriented auth3s" },
    { "shutdowns", "total connection-oriented shutdowns" },
    { "rejects", "total connection-oriented rejects" },
    { "ms_rpc_http_pdus", "total connection-oriented MS requests to send RPC over HTTP" },
    { "other_requests", "total connection-oriented other requests" },
    { "other_responses", "total connection-oriented other responses" },
    { "request_fragments", "total connection-oriented request fragments" },
    { "response_fragments", "total connection-oriented response fragments" },
    { "client_max_fragment_size", "connection-oriented client maximum fragment size" },
    { "client_min_fragment_size", "connection-oriented client minimum fragment size" },
    { "client_segs_reassembled", "total connection-oriented client segments reassembled" },
    { "client_frags_reassembled", "total connection-oriented client fragments reassembled" },
    { "server_max_fragment_size", "connection-oriented server maximum fragment size" },
    { "server_min_fragment_size", "connection-oriented server minimum fragment size" },
    { "server_segs_reassembled", "total connection-oriented server segments reassembled" },
    { "server_frags_reassembled", "total connection-oriented server fragments reassembled" },
    { "tcp_sessions", "total tcp sessions" },
    { "tcp_packets", "total tcp packets" },
    { nullptr, nullptr }
};

Dce2TcpModule::Dce2TcpModule() : Module(DCE2_TCP_NAME, DCE2_TCP_HELP, s_params)
{
}

const RuleMap* Dce2TcpModule::get_rules() const
{
    return dce2_tcp_rules;
}

const PegInfo* Dce2TcpModule::get_pegs() const
{
    return dce2_tcp_pegs;
}

PegCount* Dce2TcpModule::get_counts() const
{
    return (PegCount*)&dce2_tcp_stats;
}

ProfileStats* Dce2TcpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "dce_tcp_main";
        parent = nullptr;
        return &dce2_tcp_pstat_main;

    case 1:
        name = "dce_tcp_session";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_session;

    case 2:
        name = "dce_tcp_new_session";
        parent = "dce_tcp_session";
        return &dce2_tcp_pstat_new_session;

    case 3:
        name = "dce_tcp_detect";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_detect;

    case 4:
        name = "dce_tcp_log";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_log;

    case 5:
        name = "dce_tcp_co_segment";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_co_seg;

    case 6:
        name = "dce_tcp_co_fragment";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_co_frag;

    case 7:
        name = "dce_tcp_co_reassembly";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_co_reass;

    case 8:
        name = "dce_tcp_co_context";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_co_ctx;
    }
    return nullptr;
}

bool Dce2TcpModule::set(const char*, Value& v, SnortConfig*)
{
    if (dce2_set_co_config(v,config.common))
        return true;

    return false;
}

void Dce2TcpModule::get_data(dce2TcpProtoConf& dce2_tcp_config)
{
    dce2_tcp_config = config;
}

void print_dce2_tcp_conf(dce2TcpProtoConf& config)
{
    LogMessage("DCE TCP config: \n");
    print_dce2_co_config(config.common);
}

