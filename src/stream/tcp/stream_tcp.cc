//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_tcp.h"

#include "main/snort_config.h"

#include "tcp_ha.h"
#include "tcp_module.h"
#include "tcp_session.h"
#include "tcp_reassemblers.h"
#include "tcp_state_machine.h"

using namespace snort;

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamTcp : public Inspector
{
public:
    StreamTcp(TcpStreamConfig*);
    ~StreamTcp() override;

    void show(const SnortConfig*) const override;
    bool configure(SnortConfig*) override;
    void tinit() override;
    void tterm() override;

    NORETURN_ASSERT void eval(Packet*) override;

public:
    TcpStreamConfig* const config;
};

StreamTcp::StreamTcp (TcpStreamConfig* c)
    : config(c)
{ }

StreamTcp::~StreamTcp()
{ delete config; }

void StreamTcp::show(const SnortConfig*) const
{
    assert( config );
    config->show();
}

bool StreamTcp::configure(SnortConfig* sc)
{
    sc->max_pdu = config->paf_max;
    return true;
}

void StreamTcp::tinit()
{ TcpHAManager::tinit(); }

void StreamTcp::tterm()
{ TcpHAManager::tterm(); }

NORETURN_ASSERT void StreamTcp::eval(Packet*)
{
    // uses session::process() instead
    assert(false);
}

TcpStreamConfig* get_tcp_cfg(Inspector* ins)
{
    assert(ins);
    return ((StreamTcp*)ins)->config;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamTcpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* tcp_ctor(Module* m)
{
    StreamTcpModule* mod = (StreamTcpModule*)m;
    return new StreamTcp(mod->get_data());
}

static void tcp_dtor(Inspector* p)
{ delete p; }

static void stream_tcp_pinit()
{
    TcpStateMachine::initialize();
    TcpReassemblerFactory::initialize();
    TcpNormalizerFactory::initialize();
}

static void stream_tcp_pterm()
{
    TcpStateMachine::term();
    TcpReassemblerFactory::term();
    TcpNormalizerFactory::term();
}

static void stream_tcp_tinit()
{ TcpSession::sinit(); }

static void stream_tcp_tterm()
{ TcpSession::sterm(); }

static Session* tcp_ssn(Flow* lws)
{ return new TcpSession(lws); }

static const InspectApi tcp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        STREAM_TCP_MOD_NAME,
        STREAM_TCP_MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_STREAM,
    PROTO_BIT__TCP,
    nullptr,  // buffers
    nullptr,  // service
    stream_tcp_pinit,  // pinit
    stream_tcp_pterm,  // pterm
    stream_tcp_tinit,  // tinit,
    stream_tcp_tterm,  // tterm,
    tcp_ctor,
    tcp_dtor,
    tcp_ssn,
    nullptr   // reset
};

const BaseApi* nin_stream_tcp = &tcp_api.base;

