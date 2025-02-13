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
//
// dce_udp_module.h author Maya Dagon <mdagon@cisco.com>

#ifndef DCE2_UDP_MODULE_H
#define DCE2_UDP_MODULE_H

#include "dce_common.h"
#include "framework/module.h"

namespace snort
{
class Trace;
struct SnortConfig;
}

extern THREAD_LOCAL const snort::Trace* dce_udp_trace;

#define DCE2_CL_BAD_MAJOR_VERSION 40
#define DCE2_CL_BAD_PDU_TYPE      41
#define DCE2_CL_DATA_LT_HDR       42
#define DCE2_CL_BAD_SEQ_NUM       43

#define DCE2_CL_BAD_MAJOR_VERSION_STR "connection-less DCE/RPC - invalid major version"
#define DCE2_CL_BAD_PDU_TYPE_STR "connection-less DCE/RPC - invalid PDU type"
#define DCE2_CL_DATA_LT_HDR_STR  "connection-less DCE/RPC - data length less than header size"
#define DCE2_CL_BAD_SEQ_NUM_STR  "connection-less DCE/RPC - bad sequence number"

struct dce2UdpProtoConf
{
    dce2CommonProtoConf common = {};
};

class Dce2UdpModule : public snort::Module
{
public:
    Dce2UdpModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_DCE2; }

    const snort::RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;
    void get_data(dce2UdpProtoConf&);

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    void set_trace(const snort::Trace*) const override;
    const snort::TraceOption* get_trace_options() const override;

private:
    dce2UdpProtoConf config = {};
};

void print_dce2_udp_conf(const dce2UdpProtoConf&);

#endif

