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
// stream_icmp.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_icmp.h"

#include "log/messages.h"

#include "icmp_ha.h"
#include "icmp_module.h"
#include "icmp_session.h"

using namespace snort;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

StreamIcmpConfig::StreamIcmpConfig()
{
    session_timeout = 30;
}

static void icmp_show(StreamIcmpConfig* pc)
{
    LogMessage("Stream ICMP config:\n");
    LogMessage("    Timeout: %d seconds\n", pc->session_timeout);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamIcmp : public Inspector
{
public:
    StreamIcmp(StreamIcmpConfig*);
    ~StreamIcmp() override;

    void show(SnortConfig*) override;
    NORETURN_ASSERT void eval(Packet*) override;

private:
    StreamIcmpConfig* config;
};

StreamIcmp::StreamIcmp (StreamIcmpConfig* c)
{
    config = c;
}

StreamIcmp::~StreamIcmp()
{
    delete config;
}

void StreamIcmp::show(SnortConfig*)
{
    icmp_show(config);
}

NORETURN_ASSERT void StreamIcmp::eval(Packet*)
{
    // session::process() instead
    assert(false);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamIcmpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Session* icmp_ssn(Flow* lws)
{ return new IcmpSession(lws); }

static Inspector* icmp_ctor(Module* m)
{
    StreamIcmpModule* mod = (StreamIcmpModule*)m;
    return new StreamIcmp(mod->get_data());
}

static void icmp_tinit()
{
    IcmpHAManager::tinit();
}

static void icmp_tterm()
{
    IcmpHAManager::tterm();
}

static void icmp_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi icmp_api =
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
    PROTO_BIT__ICMP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    icmp_tinit, // tinit
    icmp_tterm, // tterm
    icmp_ctor,
    icmp_dtor,
    icmp_ssn,
    nullptr, // reset
};

const BaseApi* nin_stream_icmp = &icmp_api.base;

