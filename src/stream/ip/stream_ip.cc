//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "stream_ip.h"

#include "log/messages.h"

#include "ip_defrag.h"
#include "ip_ha.h"
#include "ip_module.h"
#include "ip_session.h"

using namespace snort;

/* max frags in a single frag tracker */
#define DEFAULT_MAX_FRAGS 8192

/* default frag timeout, 90-120 might be better values, can we do
 * engine-based quanta?  */
#define FRAG_PRUNE_QUANTA  60

/* min acceptable ttl */
#define FRAG_MIN_TTL       1

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

StreamIpConfig::StreamIpConfig()
{
    session_timeout = 60;

    frag_engine.frag_policy = FRAG_POLICY_DEFAULT;
    frag_engine.max_frags = DEFAULT_MAX_FRAGS;
    frag_engine.frag_timeout = FRAG_PRUNE_QUANTA;
    frag_engine.min_ttl = FRAG_MIN_TTL;

    frag_engine.max_overlaps = 0;
    frag_engine.min_fragment_length = 0;
}

static void ip_show(StreamIpConfig* pc)
{
    LogMessage("Stream IP config:\n");
    LogMessage("    Timeout: %d seconds\n", pc->session_timeout);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamIp : public Inspector
{
public:
    StreamIp(StreamIpConfig*);
    ~StreamIp() override;

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;

    NORETURN_ASSERT void eval(Packet*) override;

public:
    StreamIpConfig* config;
    Defrag* defrag;
};

StreamIp::StreamIp (StreamIpConfig* c)
{
    config = c;
    defrag = new Defrag(c->frag_engine);
}

StreamIp::~StreamIp()
{
    delete defrag;
    delete config;
}

bool StreamIp::configure(SnortConfig* sc)
{
    defrag->configure(sc);
    return true;
}

void StreamIp::show(SnortConfig* sc)
{
    ip_show(config);
    defrag->show(sc);
}

NORETURN_ASSERT void StreamIp::eval(Packet*)
{
    // session::process() instead
    assert(false);
}

StreamIpConfig* get_ip_cfg(Inspector* ins)
{
    assert(ins);
    return ((StreamIp*)ins)->config;
}

Defrag* get_defrag(Inspector* ins)
{
    assert(ins);
    return ((StreamIp*)ins)->defrag;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamIpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void ip_tinit()
{
    IpHAManager::tinit();
}

static void ip_tterm()
{
    IpHAManager::tterm();
}

static Inspector* ip_ctor(Module* m)
{
    StreamIpModule* mod = (StreamIpModule*)m;
    return new StreamIp(mod->get_data());
}

static void ip_dtor(Inspector* p)
{
    delete p;
}

static Session* ip_ssn(Flow* lws)
{
    return new IpSession(lws);
}

static const InspectApi ip_api =
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
    PROTO_BIT__IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    ip_tinit, // tinit
    ip_tterm, // tterm
    ip_ctor,
    ip_dtor,
    ip_ssn,
    nullptr  // reset
};

const BaseApi* nin_stream_ip = &ip_api.base;

