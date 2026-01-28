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

// opcua_module.cc author Jared Rittle <jared.rittle@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "opcua_module.h"

#include "profiler/profiler.h"

#include "opcua_session.h"

using namespace snort;

THREAD_LOCAL ProfileStats opcua_prof;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions",                "total sessions processed" },
    { CountType::SUM, "frames",                  "total OPC UA messages" },
    { CountType::NOW, "concurrent_sessions",     "total concurrent OPC UA sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent OPC UA sessions" },
    { CountType::SUM, "complete_messages",       "total reassembled OPC UA messages" },
    { CountType::SUM, "aborted_chunks",          "total aborted OPC UA message chunks" },
    { CountType::SUM, "inspector_aborts",        "number of times the service inspector aborted processing" },
    { CountType::SUM, "splitter_aborts",         "number of times the stream splitter aborted processing" },
    { CountType::SUM, "pipelined_messages",      "total number of times multiple messages were discovered in one packet" },
    { CountType::SUM, "split_messages",          "total number of times a message split across multiple packets was detected" },

    { CountType::END, nullptr,                   nullptr }
};

const PegInfo* OpcuaModule::get_pegs() const
{
    return peg_names;
}

PegCount* OpcuaModule::get_counts() const
{
    return (PegCount*)&opcua_stats;
}

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------
#define OPCUA_BAD_MSG_SIZE_STR \
    "invalid OPC UA MessageSize value detected"
#define OPCUA_ABNORMAL_MSG_SIZE_STR \
    "abnormal OPC UA MessageSize value detected"
#define OPCUA_BAD_MSG_TYPE_STR \
    "invalid OPC UA MsgType value detected"
#define OPCUA_BAD_ISFINAL_STR \
    "invalid OPC UA IsFinal value detected"
#define OPCUA_SPLIT_MSG_STR \
    "OPC UA message split across multiple packets detected"
#define OPCUA_PIPELINED_MSG_STR \
    "multiple OPC UA messages within a single frame detected"
#define OPCUA_LARGE_CHUNKED_MSG_STR \
    "large chunked OPC UA message detected"
#define OPCUA_NONZERO_NAMESPACE_INDEX_MSG_STR \
    "OPC UA message with a non-zero Namespace Index value detected"
#define OPCUA_BAD_TYPEID_ENCODING_STR \
    "OPC UA message with an invalid TypeId value detected"
#define OPCUA_ABNORMAL_PROTO_VERSION_STR \
    "OPC UA message with non-default protocol version detected"
#define OPCUA_INVALID_STRING_SIZE_STR \
    "OPC UA message with an invalid string size detected"
#define OPCUA_ABNORMAL_STRING_STR \
    "OPC UA message with an abnormal string field detected"

static const RuleMap opcua_rules[] =
{
    { OPCUA_BAD_MSG_SIZE, OPCUA_BAD_MSG_SIZE_STR },
    { OPCUA_ABNORMAL_MSG_SIZE, OPCUA_ABNORMAL_MSG_SIZE_STR  },
    { OPCUA_BAD_MSG_TYPE, OPCUA_BAD_MSG_TYPE_STR },
    { OPCUA_BAD_ISFINAL, OPCUA_BAD_ISFINAL_STR },
    { OPCUA_SPLIT_MSG, OPCUA_SPLIT_MSG_STR },
    { OPCUA_PIPELINED_MSG, OPCUA_PIPELINED_MSG_STR },
    { OPCUA_LARGE_CHUNKED_MSG, OPCUA_LARGE_CHUNKED_MSG_STR },
    { OPCUA_NONZERO_NAMESPACE_INDEX_MSG, OPCUA_NONZERO_NAMESPACE_INDEX_MSG_STR },
    { OPCUA_BAD_TYPEID_ENCODING, OPCUA_BAD_TYPEID_ENCODING_STR },
    { OPCUA_ABNORMAL_PROTO_VERSION, OPCUA_ABNORMAL_PROTO_VERSION_STR },
    { OPCUA_INVALID_STRING_SIZE, OPCUA_INVALID_STRING_SIZE_STR },
    { OPCUA_ABNORMAL_STRING, OPCUA_ABNORMAL_STRING_STR },

    { 0, nullptr }
};

const RuleMap* OpcuaModule::get_rules() const
{
    return opcua_rules;
}

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

OpcuaModule::OpcuaModule() :
    Module(OPCUA_NAME, OPCUA_HELP)
{
}

