//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "dce_tcp_module.h"
#include "dce_tcp.h"
#include "dce_common.h"
#include "main/snort_config.h"
#include "dce_co.h"

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
      "Win2000 |  WinXP | WinVista | Win2003 | Win2008 | Win7 | Samba | Samba-3.0.37 | Samba-3.0.22 | Samba-3.0.20",
      "WinXP",
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
    { "aborted sessions", "total aborted sessions" },
    { "bad autodetects", "total bad autodetects" },
    { "tcp sessions", "total tcp sessions" },
    { "tcp packets", "total tcp packets" },
    { "connection-oriented PDUs", "total connection-oriented PDUs" },
    { "connection-oriented binds", "total connection-oriented binds" },
    { "connection-oriented bind acks", "total connection-oriented binds acks" },
    { "connection-oriented alter contexts", "total connection-oriented alter contexts" },
    { "connection-oriented alter context responses",
      "total connection-oriented alter context responses" },
    { "connection-oriented bind naks", "total connection-oriented bind naks" },
    { "connection-oriented requests", "total connection-oriented requests" },
    { "connection-oriented responses", "total connection-oriented responses" },
    { "connection-oriented cancels", "total connection-oriented cancels" },
    { "connection-oriented orphaned", "total connection-oriented orphaned" },
    { "connection-oriented faults", "total connection-oriented faults" },
    { "connection-oriented auth3s", "total connection-oriented auth3s" },
    { "connection-oriented shutdowns", "total connection-oriented shutdowns" },
    { "connection-oriented rejects", "total connection-oriented rejects" },
    { "connection-oriented other requests", "total connection-oriented other requests" },
    { "connection-oriented other responses", "total connection-oriented other responses" },
    { "connection-oriented request fragments", "total connection-oriented request fragments" },
    { "connection-oriented response fragments", "total connection-oriented response fragments" },
    { "connection-oriented client maximum fragment size",
      "connection-oriented client maximum fragment size" },
    { "connection-oriented client minimum fragment size",
      "connection-oriented client minimum fragment size" },
    { "connection-oriented client segments reassembled",
      "total connection-oriented client segments reassembled" },
    { "connection-oriented client fragments reassembled",
      "total connection-oriented client fragments reassembled" },
    { "connection-oriented server maximum fragment size",
      "connection-oriented server maximum fragment size" },
    { "connection-oriented server minimum fragment size",
      "connection-oriented server minimum fragment size" },
    { "connection-oriented server segments reassembled",
      "total connection-oriented server segments reassembled" },
    { "connection-oriented server fragments reassembled",
      "total connection-oriented server fragments reassembled" },
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
        name = "dce tcp main";
        parent = nullptr;
        return &dce2_tcp_pstat_main;

    case 1:
        name = "dce tcp session";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_session;

    case 2:
        name = "dce tcp new session";
        parent = "dce tcp session";
        return &dce2_tcp_pstat_new_session;

    case 3:
        name = "dce tcp detect";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_detect;

    case 4:
        name = "dce tcp log";
        parent = "dce_tcp_main";
        return &dce2_tcp_pstat_log;

    case 5:
        name = "dce tcp connection-oriented segment";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_co_seg;

    case 6:
        name = "dce tcp connection-oriented fragment";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_co_frag;

    case 7:
        name = "dce tcp connection-oriented reassembly";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_co_reass;

    case 8:
        name = "dce tcp connection-oriented context";
        parent = "dce tcp main";
        return &dce2_tcp_pstat_co_ctx;
    }
    return nullptr;
}

bool Dce2TcpModule::set(const char*, Value& v, SnortConfig*)
{
    if (dce2_set_common_config(v,config.common))
        return true;
    else if ( v.is("reassemble_threshold") )
        config.co_reassemble_threshold = v.get_long();
    else
        return false;
    return true;
}

void Dce2TcpModule::get_data(dce2TcpProtoConf& dce2_tcp_config)
{
    dce2_tcp_config = config;
}

void print_dce2_tcp_conf(dce2TcpProtoConf& config)
{
    LogMessage("DCE TCP config: \n");

    print_dce2_common_config(config.common);
    LogMessage("    Reassemble Threshold : %d\n",
        config.co_reassemble_threshold);
}

