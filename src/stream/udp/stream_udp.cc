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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_udp.h"

#include "log/messages.h"

#include "udp_ha.h"
#include "udp_module.h"
#include "udp_session.h"

using namespace snort;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

StreamUdpConfig::StreamUdpConfig()
{
    session_timeout = 30;
}

static void udp_show(StreamUdpConfig* pc)
{
    LogMessage("Stream UDP config:\n");
    LogMessage("    Timeout: %d seconds\n", pc->session_timeout);

#ifdef REG_TEST
    LogMessage("    UDP Session Size: %zu\n", sizeof(UdpSession));
#endif
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamUdp : public Inspector
{
public:
    StreamUdp(StreamUdpConfig*);
    ~StreamUdp() override;

    void show(SnortConfig*) override;
    NORETURN_ASSERT void eval(Packet*) override;

public:
    StreamUdpConfig* config;
};

StreamUdp::StreamUdp (StreamUdpConfig* c)
{
    config = c;
}

StreamUdp::~StreamUdp()
{
    delete config;
}

void StreamUdp::show(SnortConfig*)
{
    if ( config )
        udp_show(config);
}

NORETURN_ASSERT void StreamUdp::eval(Packet*)
{
    // session::process() instead
    assert(false);
}

StreamUdpConfig* get_udp_cfg(Inspector* ins)
{
    assert(ins);
    return ((StreamUdp*)ins)->config;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamUdpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Session* udp_ssn(Flow* lws)
{
    return new UdpSession(lws);
}

static void udp_tinit()
{
    UdpHAManager::tinit();
}

static void udp_tterm()
{
    UdpHAManager::tterm();
}

static Inspector* udp_ctor(Module* m)
{
    StreamUdpModule* mod = (StreamUdpModule*)m;
    return new StreamUdp(mod->get_data());
}

static void udp_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi udp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_STREAM,
    PROTO_BIT__UDP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    udp_tinit, // tinit
    udp_tterm, // tterm
    udp_ctor,
    udp_dtor,
    udp_ssn,
    nullptr  // reset
};

const BaseApi* nin_stream_udp = &udp_api.base;

