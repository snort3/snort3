//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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

// opcua_module.h author Jared Rittle <jared.rittle@cisco.com>

#ifndef OPCUA_MODULE_H
#define OPCUA_MODULE_H

#include "framework/module.h"
#include "framework/counts.h"

#define GID_OPCUA 153

#define OPCUA_BAD_MSG_SIZE                1
#define OPCUA_ABNORMAL_MSG_SIZE           2
#define OPCUA_BAD_MSG_TYPE                3
#define OPCUA_BAD_ISFINAL                 4
#define OPCUA_SPLIT_MSG                   5
#define OPCUA_PIPELINED_MSG               6
#define OPCUA_LARGE_CHUNKED_MSG           7
#define OPCUA_NONZERO_NAMESPACE_INDEX_MSG 8
#define OPCUA_BAD_TYPEID_ENCODING         9
#define OPCUA_ABNORMAL_PROTO_VERSION      10
#define OPCUA_INVALID_STRING_SIZE         11
#define OPCUA_ABNORMAL_STRING             12

#define OPCUA_NAME    "opcua"
#define OPCUA_HELP    "opcua inspection"

struct OpcuaStats
{
    PegCount sessions;
    PegCount frames;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount complete_messages;
    PegCount aborted_chunks;
    PegCount inspector_aborts;
    PegCount splitter_aborts;
    PegCount pipelined_messages;
    PegCount split_messages;
};

extern THREAD_LOCAL OpcuaStats opcua_stats;
extern THREAD_LOCAL snort::ProfileStats opcua_prof;

class OpcuaModule : public snort::Module
{
public:
    OpcuaModule();

    unsigned get_gid() const override
    {
        return GID_OPCUA;
    }

    const snort::RuleMap* get_rules() const override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    snort::ProfileStats* get_profile() const override
    {
        return &opcua_prof;
    }

    Usage get_usage() const override
    {
        return INSPECT;
    }

    bool is_bindable() const override
    {
        return true;
    }
};

#endif

