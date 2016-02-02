//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// gtp_inspect.cc author Russ Combs <rucombs@cisco.com>
// adapt 2x preprocessor code to 3x inspector

#include "gtp_inspect.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "gtp.h"
#include "gtp_module.h"

THREAD_LOCAL GTPConfig* gtp_eval_config = nullptr;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned GtpFlowData::flow_id = 0;

void GtpFlowData::init()
{
    flow_id = FlowData::get_flow_id();
}

GtpFlowData::GtpFlowData() : FlowData(flow_id)
{
    memset(&ropts, 0, sizeof(ropts));
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class GtpInspect : public Inspector
{
public:
    GtpInspect(std::vector<GtpStuff>&);

    void eval(Packet*) override;

    int get_message_type(int version, const char* name);
    int get_info_type(int version, const char* name);

private:
    GTPConfig config;
};

GtpInspect::GtpInspect(std::vector<GtpStuff>& v)
{
    for ( unsigned i = 0; i < v.size(); ++i )
    {
        GtpStuff& gs = v[i];

        if ( gs.length < 0 )
        {
            config.msgv[gs.version][gs.type].name = gs.name;
        }
        else
        {
            config.infov[gs.version][gs.type].name = gs.name;
            config.infov[gs.version][gs.type].length = gs.length;
        }
    }
}

void GtpInspect::eval(Packet* p)
{
    Profile profile(gtp_inspect_prof);

    // preconditions - what we registered for
    assert(p->has_udp_data());

    gtp_eval_config = &config;
    GTPmain(p);
}

//-------------------------------------------------------------------------
// public lookups
//-------------------------------------------------------------------------

int GtpInspect::get_message_type(int version, const char* name)
{
    if ( version < 0 or version > MAX_GTP_VERSION_CODE )
        return -1;

    for ( int i = 0; i <= MAX_GTP_TYPE_CODE; ++i )
        if ( config.msgv[version][i].name == name )
            return i;

    return -1;
}

int get_message_type(int version, const char* name)
{
    GtpInspect* ins = (GtpInspect*)InspectorManager::get_inspector(GTP_NAME);

    if ( !ins )
        return -1;

    return ins->get_message_type(version, name);
}

int GtpInspect::get_info_type(int version, const char* name)
{
    if ( version < 0 or version > MAX_GTP_VERSION_CODE )
        return -1;

    for ( int i = 0; i <= MAX_GTP_TYPE_CODE; ++i )
        if ( config.infov[version][i].name == name )
            return i;

    return -1;
}

int get_info_type(int version, const char* name)
{
    GtpInspect* ins = (GtpInspect*)InspectorManager::get_inspector(GTP_NAME);

    if ( !ins )
        return -1;

    return ins->get_info_type(version, name);
}

//-------------------------------------------------------------------------
// plugin stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new GtpInspectModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void gtp_init()
{
    GtpFlowData::init();
}

static void gtp_term()
{
}

static Inspector* gtp_ctor(Module* m)
{
    GtpInspectModule* mod = (GtpInspectModule*)m;
    // this move assures the stuff is cleared
    std::vector<GtpStuff> v = std::move(mod->config);
    return new GtpInspect(v);
}

static void gtp_dtor(Inspector* p)
{
    delete p;
}

//-------------------------------------------------------------------------

static const InspectApi gtp_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        GTP_NAME,
        GTP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::UDP,
    nullptr,
    "gtp",
    gtp_init,
    gtp_term,
    nullptr, // tinit
    nullptr, // tterm
    gtp_ctor,
    gtp_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
extern const BaseApi* ips_gtp_info;
extern const BaseApi* ips_gtp_type;
extern const BaseApi* ips_gtp_version;

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &gtp_api.base,
    ips_gtp_info,
    ips_gtp_type,
    ips_gtp_version,
    nullptr
};
#else
const BaseApi* sin_gtp = &gtp_api.base;
#endif

