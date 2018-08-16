//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// dce_http_server.cc author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_http_server_module.h"

#include "managers/inspector_manager.h"
#include "stream/libtcp/tcp_stream_session.h"

#include "dce_http_server_splitter.h"

using namespace snort;

THREAD_LOCAL DceHttpServerStats dce_http_server_stats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class DceHttpServer : public Inspector
{
public:
    void eval(Packet*) override { }
    void clear(Packet*) override;
    StreamSplitter* get_splitter(bool c2s) override
    {
        return new DceHttpServerSplitter(c2s);
    }
};

void DceHttpServer::clear(Packet* p)
{
    Flow* flow = p->flow;

    if (flow->session and flow->pkt_type == PktType::TCP)
    {
        if ( !p->test_session_flags(SSNFLAG_ABORT_SERVER) )
        {
            TcpStreamSession* tcp_session = (TcpStreamSession*)flow->session;
            DceHttpServerSplitter* splitter =
                (DceHttpServerSplitter*)(tcp_session->get_splitter(false));

            if ( splitter->cutover_inspector())
            {
                dce_http_server_stats.http_server_sessions++;
                flow->set_service(p, DCE_RPC_SERVICE_NAME);
            }
            else
                dce_http_server_stats.http_server_session_failures++;
        }
        else
            dce_http_server_stats.http_server_session_failures++;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_server_ctor()
{
    return new DceHttpServerModule;
}

static void mod_server_dtor(Module* m)
{
    delete m;
}

static Inspector* dce_http_server_ctor(Module*)
{
    return new DceHttpServer();
}

static void dce_http_server_dtor(Inspector* p)
{
    delete p;
}

const InspectApi dce_http_server_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE_HTTP_SERVER_NAME,
        DCE_HTTP_SERVER_HELP,
        mod_server_ctor,
        mod_server_dtor
    },
    IT_SERVICE,
    PROTO_BIT__PDU,
    nullptr,  // buffers
    "dce_http_server",
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce_http_server_ctor,
    dce_http_server_dtor,
    nullptr, // ssn
    nullptr  // reset
};

