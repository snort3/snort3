//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// dce_http_proxy.cc author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_http_common.h"
#include "dce_http_proxy_module.h"
#include "dce_http_proxy_splitter.h"

#include "managers/inspector_manager.h"
#include "stream/libtcp/tcp_stream_session.h"

THREAD_LOCAL DceHttpProxyStats dce_http_proxy_stats;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class DceHttpProxy : public Inspector
{
public:
    void eval(Packet*) override { }
    void clear(Packet*) override;
    StreamSplitter* get_splitter(bool c2s) override
    {
        return new DceHttpProxySplitter(c2s);
    }
};

void DceHttpProxy::clear(Packet* p)
{
    Flow* flow = p->flow;
    TcpStreamSession* session;

    if ( flow->session != nullptr)
    {
        if ( (flow->get_session_flags() & (SSNFLAG_ABORT_CLIENT | SSNFLAG_ABORT_SERVER)) == 0 )
        {
            session = (TcpStreamSession*)flow->session;
            DceHttpProxySplitter* c2s_splitter = (DceHttpProxySplitter*)(session->get_splitter(true));
            DceHttpProxySplitter* s2c_splitter = (DceHttpProxySplitter*)(session->get_splitter(false));
            if ( c2s_splitter->cutover_inspector() && s2c_splitter->cutover_inspector() )
            {
                dce_http_proxy_stats.http_proxy_sessions++;
                dce_http_bind(flow, "dce_tcp");
            }
            else
                dce_http_proxy_stats.http_proxy_session_failures++;
        }
        else
            dce_http_proxy_stats.http_proxy_session_failures++;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_proxy_ctor()
{
    return new DceHttpProxyModule;
}

static void mod_proxy_dtor(Module* m)
{
    delete m;
}

static Inspector* dce_http_proxy_ctor(Module*)
{
    return new DceHttpProxy();
}

static void dce_http_proxy_dtor(Inspector* p)
{
    delete p;
}

const InspectApi dce_http_proxy_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        DCE_HTTP_PROXY_NAME,
        DCE_HTTP_PROXY_HELP,
        mod_proxy_ctor,
        mod_proxy_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr,  // buffers
    "dce_http_proxy",
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dce_http_proxy_ctor,
    dce_http_proxy_dtor,
    nullptr, // ssn
    nullptr  // reset
};

