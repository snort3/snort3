//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;
using namespace std;

static const Parameter s_params[] =
{
    { "limit_alerts", Parameter::PT_BOOL, nullptr, "true",
      "limit DCE alert to at most one per signature per flow" },

    { "disable_defrag", Parameter::PT_BOOL, nullptr, "false",
      "disable DCE/RPC defragmentation" },

    { "max_frag_len", Parameter::PT_INT, "1514:65535", "65535",
      "maximum fragment size for defragmentation" },

    { "reassemble_threshold", Parameter::PT_INT, "0:65535", "0",
      "minimum bytes received before performing reassembly" },

    { "policy", Parameter::PT_ENUM,
      "Win2000 |  WinXP | WinVista | Win2003 | Win2008 | Win7 | "
      "Samba | Samba-3.0.37 | Samba-3.0.22 | Samba-3.0.20", "WinXP",
      "target based policy to use" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dce2_tcp_rules[] =
{
    { DCE2_CO_BAD_MAJOR_VERSION, DCE2_CO_BAD_MAJOR_VERSION_STR },
    { DCE2_CO_BAD_MINOR_VERSION, DCE2_CO_BAD_MINOR_VERSION_STR },
    { DCE2_CO_BAD_PDU_TYPE, DCE2_CO_BAD_PDU_TYPE_STR },
    { DCE2_CO_FRAG_LEN_LT_HDR, DCE2_CO_FRAG_LEN_LT_HDR_STR },
    { DCE2_CO_REM_FRAG_LEN_LT_SIZE, DCE2_CO_REM_FRAG_LEN_LT_SIZE_STR },
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
    { CountType::SUM, "events", "total events" },
    { CountType::SUM, "pdus", "total connection-oriented PDUs" },
    { CountType::SUM, "binds", "total connection-oriented binds" },
    { CountType::SUM, "bind_acks", "total connection-oriented binds acks" },
    { CountType::SUM, "alter_contexts", "total connection-oriented alter contexts" },
    { CountType::SUM, "alter_context_responses", "total connection-oriented alter context responses" },
    { CountType::SUM, "bind_naks", "total connection-oriented bind naks" },
    { CountType::SUM, "requests", "total connection-oriented requests" },
    { CountType::SUM, "responses", "total connection-oriented responses" },
    { CountType::SUM, "cancels", "total connection-oriented cancels" },
    { CountType::SUM, "orphaned", "total connection-oriented orphaned" },
    { CountType::SUM, "faults", "total connection-oriented faults" },
    { CountType::SUM, "auth3s", "total connection-oriented auth3s" },
    { CountType::SUM, "shutdowns", "total connection-oriented shutdowns" },
    { CountType::SUM, "rejects", "total connection-oriented rejects" },
    { CountType::SUM, "ms_rpc_http_pdus", "total connection-oriented MS requests to send RPC over HTTP" },
    { CountType::SUM, "other_requests", "total connection-oriented other requests" },
    { CountType::SUM, "other_responses", "total connection-oriented other responses" },
    { CountType::SUM, "request_fragments", "total connection-oriented request fragments" },
    { CountType::SUM, "response_fragments", "total connection-oriented response fragments" },
    { CountType::MAX, "client_max_fragment_size", "connection-oriented client maximum fragment size" },
    { CountType::SUM, "client_min_fragment_size", "connection-oriented client minimum fragment size" },
    { CountType::SUM, "client_segs_reassembled", "total connection-oriented client segments reassembled" },
    { CountType::SUM, "client_frags_reassembled", "total connection-oriented client fragments reassembled" },
    { CountType::MAX, "server_max_fragment_size", "connection-oriented server maximum fragment size" },
    { CountType::SUM, "server_min_fragment_size", "connection-oriented server minimum fragment size" },
    { CountType::SUM, "server_segs_reassembled", "total connection-oriented server segments reassembled" },
    { CountType::SUM, "server_frags_reassembled", "total connection-oriented server fragments reassembled" },
    { CountType::SUM, "tcp_sessions", "total tcp sessions" },
    { CountType::SUM, "tcp_expected_sessions", "total tcp dynamic endpoint expected sessions" },
    { CountType::SUM, "tcp_expected_realized", "total tcp dynamic endpoint expected realized sessions" },
    { CountType::SUM, "tcp_packets", "total tcp packets" },
    { CountType::NOW, "concurrent_sessions", "total concurrent sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent sessions" },
    { CountType::END, nullptr, nullptr }
};

Dce2TcpModule::Dce2TcpModule() : Module(DCE2_TCP_NAME, DCE2_TCP_HELP, s_params)
{ }

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

ProfileStats* Dce2TcpModule::get_profile() const
{
    return &dce2_tcp_pstat_main;
}

bool Dce2TcpModule::set(const char*, Value& v, SnortConfig*)
{
    return dce2_set_co_config(v,config.common);
}

void Dce2TcpModule::get_data(dce2TcpProtoConf& dce2_tcp_config)
{
    dce2_tcp_config = config;
}

void print_dce2_tcp_conf(const dce2TcpProtoConf& config)
{
    print_dce2_co_config(config.common);
}

