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

// gtp_inspect.cc author Russ Combs <rucombs@cisco.com>
// adapt 2x preprocessor code to 3x inspector

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gtp_inspect.h"

#include "detection/detection_engine.h"
#include "detection/ips_context.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "gtp.h"
#include "gtp_module.h"

using namespace snort;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------

unsigned GtpFlowData::inspector_id = 0;

void GtpFlowData::init()
{
    inspector_id = FlowData::create_flow_data_id();
}

GtpFlowData::GtpFlowData() : FlowData(inspector_id)
{
    memset(&ropts, 0, sizeof(ropts));
    gtp_stats.concurrent_sessions++;
    if(gtp_stats.max_concurrent_sessions < gtp_stats.concurrent_sessions)
        gtp_stats.max_concurrent_sessions = gtp_stats.concurrent_sessions;
}

GtpFlowData::~GtpFlowData()
{
    assert(gtp_stats.concurrent_sessions > 0);
    gtp_stats.concurrent_sessions--;
}

//-------------------------------------------------------------------------
// ips context stuff
//-------------------------------------------------------------------------

static unsigned ips_id = 0;

// This table stores all the information elements in a packet
// To save memory, only one table for each ips context.
//
// The information in the table might from previous packet,
// use msg_id to find out whether the information is current.

class GtpContextData : public IpsContextData
{
public:
    GtpContextData()
    { memset(gtp_ies, 0, sizeof(gtp_ies)); }

    static void init()
    { ips_id = IpsContextData::get_ips_id(); }

    GTP_IEData gtp_ies[MAX_GTP_IE_CODE + 1];
};

GTP_IEData* get_infos()
{
    GtpContextData* gcd = (GtpContextData*)DetectionEngine::get_data(ips_id);

    if ( !gcd )
    {
        gcd = new GtpContextData;
        DetectionEngine::set_data(ips_id, gcd);
    }
    return gcd->gtp_ies;
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

    GTPmain(config, p);
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
    GtpContextData::init();
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
    PROTO_BIT__UDP,
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

extern const BaseApi* ips_gtp_info;
extern const BaseApi* ips_gtp_type;
extern const BaseApi* ips_gtp_version;

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* sin_gtp[] =
#endif
{
    &gtp_api.base,
    ips_gtp_info,
    ips_gtp_type,
    ips_gtp_version,
    nullptr
};

