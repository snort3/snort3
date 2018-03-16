//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// ips_flow.cc derived from sp_clientserver.c by Martin Roesch

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_flow.h"

#include "detection/treenodes.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "target_based/snort_protocols.h"

using namespace snort;

#define s_name "flow"

static THREAD_LOCAL ProfileStats flowCheckPerfStats;

#define ONLY_STREAM   0x01
#define ONLY_FRAG     0x02
#define IGNORE_STREAM 0x01
#define IGNORE_FRAG   0x02

struct FlowCheckData
{
    uint8_t from_server;
    uint8_t from_client;
    uint8_t ignore_reassembled;
    uint8_t only_reassembled;
    uint8_t stateless;
    uint8_t established;
    uint8_t unestablished;
};

class FlowCheckOption : public IpsOption
{
public:
    FlowCheckOption(const FlowCheckData& c) : IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

//private:
    FlowCheckData config;  // FIXIT-L privatize
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FlowCheckOption::hash() const
{
    uint32_t a,b,c;
    const FlowCheckData* data = &config;

    a = data->from_server | (data->from_client << 16);
    b = data->ignore_reassembled | (data->only_reassembled << 16);
    c = data->stateless | (data->established << 16);

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    a += data->unestablished;
    finalize(a,b,c);

    return c;
}

bool FlowCheckOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const FlowCheckOption& rhs = (const FlowCheckOption&)ips;
    const FlowCheckData* left = &config;
    const FlowCheckData* right = &rhs.config;

    if (( left->from_server == right->from_server) &&
        ( left->from_client == right->from_client) &&
        ( left->ignore_reassembled == right->ignore_reassembled) &&
        ( left->only_reassembled == right->only_reassembled) &&
        ( left->stateless == right->stateless) &&
        ( left->established == right->established) &&
        ( left->unestablished == right->unestablished))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus FlowCheckOption::eval(Cursor&, Packet* p)
{
    Profile profile(flowCheckPerfStats);

    FlowCheckData* fcd = &config;

    // Check established/unestablished first
    {
        if ((fcd->established == 1) && !(p->packet_flags & PKT_STREAM_EST))
        {
            // This option requires an established connection and it isn't
            // in that state yet, so no match.
            return NO_MATCH;
        }
        else if ((fcd->unestablished == 1) && (p->packet_flags & PKT_STREAM_EST))
        {
            //  We're looking for an unestablished stream, and this is
            //  established, so don't continue processing.
            return NO_MATCH;
        }
    }

    // Now check from client
    if (fcd->from_client)
    {
        {
            if (!p->is_from_client() && p->is_from_server())
            {
                // No match on from_client
                return NO_MATCH;
            }
        }
    }

    // And from server
    if (fcd->from_server)
    {
        {
            if (!p->is_from_server() && p->is_from_client())
            {
                // No match on from_server
                return NO_MATCH;
            }
        }
    }

    // ...ignore_reassembled
    if (fcd->ignore_reassembled & IGNORE_STREAM)
    {
        if (p->packet_flags & PKT_REBUILT_STREAM)
        {
            return NO_MATCH;
        }
    }

    if (fcd->ignore_reassembled & IGNORE_FRAG)
    {
        if (p->packet_flags & PKT_REBUILT_FRAG)
        {
            return NO_MATCH;
        }
    }

    // ...only_reassembled
    if (fcd->only_reassembled & ONLY_STREAM)
    {
        if ( !p->has_paf_payload() )
        {
            return NO_MATCH;
        }
    }

    if (fcd->only_reassembled & ONLY_FRAG)
    {
        if (!(p->packet_flags & PKT_REBUILT_FRAG))
        {
            return NO_MATCH;
        }
    }

    return MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

int OtnFlowFromServer(OptTreeNode* otn)
{
    FlowCheckOption* fco =
        (FlowCheckOption*)get_rule_type_data(otn, s_name);

    if (fco )
    {
        if ( fco->config.from_server )
            return 1;
    }
    return 0;
}

int OtnFlowFromClient(OptTreeNode* otn)
{
    FlowCheckOption* fco =
        (FlowCheckOption*)get_rule_type_data(otn, s_name);

    if (fco )
    {
        if ( fco->config.from_client )
            return 1;
    }
    return 0;
}

//-------------------------------------------------------------------------
// support methods
//-------------------------------------------------------------------------

static void flow_verify(FlowCheckData* fcd)
{
    if (fcd->from_client && fcd->from_server)
    {
        ParseError("can't use both from_client and flow_from server");
        return;
    }

    if ((fcd->ignore_reassembled & IGNORE_STREAM) && (fcd->only_reassembled & ONLY_STREAM))
    {
        ParseError("can't use no_stream and only_stream");
        return;
    }

    if ((fcd->ignore_reassembled & IGNORE_FRAG) && (fcd->only_reassembled & ONLY_FRAG))
    {
        ParseError("can't use no_frag and only_frag");
        return;
    }

    if (fcd->stateless && (fcd->from_client || fcd->from_server))
    {
        ParseError("can't use flow: stateless option with other options");
        return;
    }

    if (fcd->stateless && fcd->established)
    {
        ParseError("can't specify established and stateless "
            "options in same rule");
        return;
    }

    if (fcd->stateless && fcd->unestablished)
    {
        ParseError("can't specify unestablished and stateless "
            "options in same rule");
        return;
    }

    if (fcd->established && fcd->unestablished)
    {
        ParseError("can't specify unestablished and established "
            "options in same rule");
        return;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "to_client", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on server responses" },

    { "to_server", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on client requests" },

    { "from_client", Parameter::PT_IMPLIED, nullptr, nullptr,
      "same as to_server" },

    { "from_server", Parameter::PT_IMPLIED, nullptr, nullptr,
      "same as to_client" },

    { "established", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match only during data transfer phase" },

    { "not_established", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match only outside data transfer phase" },

    { "stateless", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match regardless of stream state" },

    { "no_stream", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on raw packets only" },

    { "only_stream", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on reassembled packets only" },

    { "no_frag", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on raw packets only" },

    { "only_frag", Parameter::PT_IMPLIED, nullptr, nullptr,
      "match on defragmented packets only" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check session properties"

class FlowModule : public Module
{
public:
    FlowModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &flowCheckPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    FlowCheckData data;
};

bool FlowModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    return true;
}

bool FlowModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("to_server") )
        data.from_client = 1;

    else if ( v.is("to_client") )
        data.from_server = 1;

    else if ( v.is("from_server") )
        data.from_server = 1;

    else if ( v.is("from_client") )
        data.from_client = 1;

    else if ( v.is("stateless") )
        data.stateless = 1;

    else if ( v.is("established") )
        data.established = 1;

    else if ( v.is("not_established") )
        data.unestablished = 1;

    else if ( v.is("no_stream") )
        data.ignore_reassembled |= IGNORE_STREAM;

    else if ( v.is("only_stream") )
        data.only_reassembled |= ONLY_STREAM;

    else if ( v.is("no_frag") )
        data.ignore_reassembled |= IGNORE_FRAG;

    else if ( v.is("only_frag") )
        data.only_reassembled |= ONLY_FRAG;

    else
        return false;

    flow_verify(&data);
    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlowModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* flow_ctor(Module* p, OptTreeNode* otn)
{
    FlowModule* m = (FlowModule*)p;

    if ( m->data.stateless )
        otn->stateless = 1;

    if ( m->data.established )
        otn->established = 1;

    if ( m->data.unestablished )
        otn->unestablished = 1;

    if (otn->snort_protocol_id == SNORT_PROTO_ICMP)
    {
        if ( (m->data.only_reassembled != ONLY_FRAG) &&
            (m->data.ignore_reassembled != IGNORE_FRAG) )
        {
            ParseError("Cannot check flow connection for ICMP traffic");
            return nullptr;
        }
    }
    return new FlowCheckOption(m->data);
}

static void flow_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi flow_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    flow_ctor,
    flow_dtor,
    nullptr
};

const BaseApi* ips_flow = &flow_api.base;

