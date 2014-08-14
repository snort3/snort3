/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "stream_tcp.h"
#include "tcp_module.h"
#include "tcp_session.h"

#include "main/snort.h"
#include "stream/flush_bucket.h"

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamTcp : public Inspector
{
public:
    StreamTcp(StreamTcpConfig*);
    ~StreamTcp();

    int verify_config(SnortConfig*);
    void show(SnortConfig*);

    void tinit();
    void tterm();

    void eval(Packet*);

public:
    StreamTcpConfig* config;
};

StreamTcp::StreamTcp (StreamTcpConfig* c)
{
    config = c;
}

StreamTcp::~StreamTcp()
{
    delete config;
}

int StreamTcp::verify_config(SnortConfig* sc)
{
    return Stream5VerifyTcpConfig(sc, config);
}

void StreamTcp::show(SnortConfig*)
{
    tcp_show(config);
}

void StreamTcp::tinit()
{
    FlushBucket* fb;

    if ( config->footprint )
        fb = new ConstFlushBucket(config->footprint);

    else if ( ScStaticHash() )
        fb = new StaticFlushBucket;

    else
        fb = new RandomFlushBucket;

    FlushBucket::set(fb);
}

void StreamTcp::tterm()
{
    //FlushBucket::clear();  FIXIT must be called after StreamBase::tterm()
}

void StreamTcp::eval(Packet*)
{
    // uses session::process() instead
    assert(false);
}

StreamTcpConfig* get_tcp_cfg(Inspector* ins)
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
{
    delete p;
}

Session* tcp_ssn(Flow* lws)
{
    return new TcpSession(lws);
}

void tcp_tinit()
{
    tcp_sinit();
}

void tcp_tterm()
{
    tcp_sterm();
}

static const InspectApi tcp_api =
{
    {
        PT_INSPECTOR,
        MOD_NAME,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_STREAM,
    PROTO_BIT__TCP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    tcp_tinit,
    tcp_tterm,
    tcp_ctor,
    tcp_dtor,
    tcp_ssn,
    tcp_reset
};

const BaseApi* nin_stream_tcp = &tcp_api.base;

