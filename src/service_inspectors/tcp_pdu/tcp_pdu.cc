//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_pdu.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "profiler/profiler.h"

#include "tcp_pdu.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// common foo
//-------------------------------------------------------------------------

#define s_name "tcp_pdu"
#define s_help "set TCP flush points based on PDU length field"

static const PegInfo pdu_pegs[] =
{
    { CountType::SUM, "scans", "total segments scanned" },
    { CountType::SUM, "flushes", "total PDUs flushed for detection" },
    { CountType::SUM, "aborts", "total unrecoverable scan errors" },
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL PduCounts pdu_counts;

static THREAD_LOCAL snort::ProfileStats pdu_prof;

//-------------------------------------------------------------------------
// module foo
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "offset", Parameter::PT_INT, "0:65535", "0",
      "index to first byte of length field" },

    { "size", Parameter::PT_INT, "1:4", "4",
      "number of bytes in length field" },

    { "skip", Parameter::PT_INT, "0:65535", "0",
      "bytes after length field to end of header" },

    { "relative", Parameter::PT_BOOL, nullptr, "false",
      "extracted length follows field (instead of whole PDU)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class TcpPduModule : public snort::Module
{
public:
    TcpPduModule() : Module(s_name, s_help, s_params)
    { }

    const PegInfo* get_pegs() const override
    { return pdu_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&pdu_counts; }

    snort::ProfileStats* get_profile() const override
    { return &pdu_prof; }

    Usage get_usage() const override
    { return INSPECT; }

    bool is_bindable() const override
    { return true; }

    bool set(const char*, Value&, SnortConfig*) override;

    TcpPduConfig& get_config()
    { return config; }

private:
    TcpPduConfig config;
};

bool TcpPduModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("offset"))
        config.offset = v.get_int32();

    else if (v.is("size"))
        config.size = v.get_uint8();

    else if (v.is("skip"))
        config.skip = v.get_uint8();

    else if (v.is("relative"))
        config.relative = v.get_bool();

    return true;
}

//-------------------------------------------------------------------------
// inspector foo
//-------------------------------------------------------------------------

class TcpPdu : public Inspector
{
public:
    TcpPdu(TcpPduConfig& c) : config(c) { }

    StreamSplitter* get_splitter(bool c2s) override
    { return new TcpPduSplitter(c2s, config); }

private:
    TcpPduConfig config;
};

//-------------------------------------------------------------------------
// api foo
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TcpPduModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* pdu_ctor(Module* m)
{
    TcpPduModule* tpm = (TcpPduModule*)m;
    return new TcpPdu(tpm->get_config());
}

static void pdu_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi pdu_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr, // buffers
    s_name,
    nullptr, // init
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    pdu_ctor,
    pdu_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pdu_api.base,
    nullptr
};
#else
const BaseApi* sin_tcp_pdu = &pdu_api.base;
#endif

