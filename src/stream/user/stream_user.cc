//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// stream_user.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_user.h"

#include "log/messages.h"

#include "user_module.h"
#include "user_session.h"

using namespace snort;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

StreamUserConfig::StreamUserConfig()
{
    session_timeout = 60;
}

static void user_show (StreamUserConfig* pc)
{
    LogMessage("Stream user config:\n");
    LogMessage("    Timeout: %d seconds\n", pc->session_timeout);
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamUser : public Inspector
{
public:
    StreamUser(StreamUserConfig*);
    ~StreamUser() override;

    void show(SnortConfig*) override;

    NORETURN_ASSERT void eval(Packet*) override;

public:
    StreamUserConfig* config;
};

StreamUser::StreamUser (StreamUserConfig* c)
{
    config = c;
}

StreamUser::~StreamUser()
{
    delete config;
}

void StreamUser::show(SnortConfig*)
{
    user_show(config);
}

NORETURN_ASSERT void StreamUser::eval(Packet*)
{
    // session::process() instead
    assert(false);
}

StreamUserConfig* get_user_cfg(Inspector* ins)
{
    assert(ins);
    return ((StreamUser*)ins)->config;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamUserModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* user_ctor(Module* m)
{
    StreamUserModule* mod = (StreamUserModule*)m;
    return new StreamUser(mod->get_data());
}

static void user_dtor(Inspector* p)
{
    delete p;
}

static Session* user_ssn(Flow* lws)
{
    return new UserSession(lws);
}

static const InspectApi user_api =
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
    PROTO_BIT__PDU,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    user_ctor,
    user_dtor,
    user_ssn,
    nullptr  // reset
};

const BaseApi* nin_stream_user = &user_api.base;

