//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// gtp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gtp_module.h"

#include <cassert>

#include "profiler/profiler.h"

#include "gtp.h"

using namespace snort;

Trace TRACE_NAME(gtp_inspect);
THREAD_LOCAL ProfileStats gtp_inspect_prof;

#define GTP_EVENT_BAD_MSG_LEN_STR        "message length is invalid"
#define GTP_EVENT_BAD_IE_LEN_STR         "information element length is invalid"
#define GTP_EVENT_OUT_OF_ORDER_IE_STR    "information elements are out of order"

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

const PegInfo peg_names[] =
{
    { CountType::SUM, "sessions", "total sessions processed" },
    { CountType::NOW, "concurrent_sessions", "total concurrent gtp sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent gtp sessions" },
    { CountType::SUM, "events", "requests" },
    { CountType::SUM, "unknown_types", "unknown message types" },
    { CountType::SUM, "unknown_infos", "unknown information elements" },

    { CountType::END, nullptr, nullptr }
};

const PegInfo* GtpInspectModule::get_pegs() const
{ return peg_names; }

PegCount* GtpInspectModule::get_counts() const
{ return (PegCount*)&gtp_stats; }

//-------------------------------------------------------------------------
// rules
//-------------------------------------------------------------------------

static const RuleMap gtp_rules[] =
{
    { GTP_EVENT_BAD_MSG_LEN, GTP_EVENT_BAD_MSG_LEN_STR },
    { GTP_EVENT_BAD_IE_LEN, GTP_EVENT_BAD_IE_LEN_STR },
    { GTP_EVENT_OUT_OF_ORDER_IE, GTP_EVENT_OUT_OF_ORDER_IE_STR },

    { 0, nullptr }
};

const RuleMap* GtpInspectModule::get_rules() const
{ return gtp_rules; }

//-------------------------------------------------------------------------
// params
//-------------------------------------------------------------------------

static const Parameter gtp_msg_params[] =
{
    { "type", Parameter::PT_INT, "0:255", "0",
      "message type code" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "message name" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter gtp_info_params[] =
{
    { "type", Parameter::PT_INT, "0:255", "0",
      "information element type code" },

    { "name", Parameter::PT_STRING, nullptr, nullptr,
      "information element name" },

    { "length", Parameter::PT_INT, "0:255", "0",
      "information element type code" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const Parameter gtp_params[] =
{
    { "version", Parameter::PT_INT, "0:2", "2",
      "GTP version" },

    { "messages", Parameter::PT_LIST, gtp_msg_params, nullptr,
      "message dictionary" },

    { "infos", Parameter::PT_LIST, gtp_info_params, nullptr,
      "information element dictionary" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

GtpInspectModule::GtpInspectModule() :
    Module(GTP_NAME, GTP_HELP, gtp_params, true, &TRACE_NAME(gtp_inspect))
{ }

bool GtpInspectModule::set(const char* fqn, Value& v, SnortConfig* c)
{
    if ( v.is("version") )
        stuff.version = v.get_long();

    else if ( v.is("type") )
        stuff.type = v.get_long();

    else if ( v.is("length") )
        stuff.length = v.get_long();

    else if ( v.is("name") )
        stuff.name = v.get_string();

    else
        return Module::set(fqn, v, c);

    return true;
}

bool GtpInspectModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( !strcmp(fqn, "gtp_inspect") and !idx )
    {
        temp.clear();
        config.clear();
    }

    // version persists
    stuff.name.clear();
    stuff.type = 0;
    stuff.length = -1;

    return true;
}

// we may not get current version until after lists are loaded
// so the lists go to temp and when the list item is closed we
// move to the main config.
bool GtpInspectModule::end(const char* fqn, int idx, SnortConfig*)
{
    if ( !strcmp(fqn, "gtp_inspect") and idx )
    {
        for ( unsigned i = 0; i < temp.size(); ++i )
        {
            temp[i].version = stuff.version;
            config.push_back(temp[i]);
        }
        temp.clear();
    }
    else if ( !strcmp(fqn, "gtp_inspect.messages") and idx )
    {
        assert(stuff.length < 0);
        temp.push_back(stuff);
    }
    else if ( !strcmp(fqn, "gtp_inspect.infos") and idx )
    {
        assert(stuff.length >= 0);
        temp.push_back(stuff);
    }
    return true;
}
