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
// stream_file.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_file.h"

#include "file_module.h"
#include "file_session.h"

using namespace snort;

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamFile : public Inspector
{
public:
    StreamFile(bool b)
    { config.upload = b; }

    NORETURN_ASSERT void eval(Packet*) override;

    StreamFileConfig config;
};

NORETURN_ASSERT void StreamFile::eval(Packet*)
{
    // session::process() instead
    assert(false);
}

StreamFileConfig* get_file_cfg(Inspector* ins)
{
    assert(ins);
    return &((StreamFile*)ins)->config;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamFileModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* file_ctor(Module* m)
{
    StreamFileModule* mod = (StreamFileModule*)m;
    return new StreamFile(mod->upload);
}

static void file_dtor(Inspector* p)
{
    delete p;
}

static Session* file_ssn(Flow* lws)
{
    return new FileSession(lws);
}

static const InspectApi sfile_api =
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
    PROTO_BIT__FILE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    file_ctor,
    file_dtor,
    file_ssn,
    nullptr  // reset
};

const BaseApi* nin_stream_file = &sfile_api.base;

