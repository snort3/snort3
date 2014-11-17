/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// inspector_manager.cc author Russ Combs <rucombs@cisco.com>

#include "inspector_manager.h"

#include <assert.h>
#include <algorithm>
#include <list>
#include <vector>

#include "module_manager.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "framework/inspector.h"
#include "detection/detection_util.h"
#include "obfuscation.h"
#include "packet_io/active.h"
#include "ppm.h"
#include "snort.h"
#include "log/messages.h"
#include "target_based/sftarget_protocol_reference.h"
#include "binder/bind_module.h"

using namespace std;

// FIXIT-L should be using IT_* instead or at least define once
#define bind_id "binder"
#define wiz_id "wizard"

//-------------------------------------------------------------------------
// list stuff
//-------------------------------------------------------------------------
// it will be possible to load new processor so's, even newer versions of
// previously loaded so's, on reload

// class vs instance is currently a little off.  class corresponds to config
// while instance corresponds to policy.  we need to keep "context" in class
// for now since that is needed to config things like post-config-init.
// this distinction should be more precise when policy foo is ripped out of
// the instances.

struct PHGlobal
{
    const InspectApi& api;
    bool init;  // call api.pinit()

    PHGlobal(const InspectApi& p) : api(p)
    { init = true; };

    static bool comp (const PHGlobal* a, const PHGlobal* b)
    { return ( a->api.type < b->api.type ); };
};

struct PHClass
{
    const InspectApi& api;
    bool init;  // call pin->tinit()
    bool term;  // call pin->tterm()

    PHClass(const InspectApi& p) : api(p)
    { init = term = true; };

    static bool comp (PHClass* a, PHClass* b)
    { return ( a->api.type < b->api.type ); };
};

struct PHInstance
{
    PHClass& pp_class;
    Inspector* handler;
    string name;

    PHInstance(PHClass&);
    ~PHInstance();

    static bool comp (PHInstance* a, PHInstance* b)
    { return ( a->pp_class.api.type < b->pp_class.api.type ); };

    void set_name(const char* s)
    { name = s; };
};

PHInstance::PHInstance(PHClass& p) : pp_class(p)
{
    Module* mod = ModuleManager::get_module(p.api.base.name);
    handler = p.api.ctor(mod);

    if ( handler )
    {
        handler->set_api(&p.api);
        handler->add_ref();
    }
}

PHInstance::~PHInstance()
{
    if ( handler )
        handler->rem_ref();
}

typedef vector<PHGlobal*> PHGlobalList;
typedef vector<PHClass*> PHClassList;
typedef vector<PHInstance*> PHInstanceList;
typedef list<Inspector*> PHList;

static PHGlobalList s_handlers;
static PHList s_trash;

struct FrameworkConfig
{
    PHClassList clist;
};

struct PHVector
{
    PHInstance** vec;
    unsigned num;

    PHVector()
    { vec = nullptr; num = 0; };

    ~PHVector()
    { if ( vec ) delete[] vec; };

    void alloc(unsigned max)
    { vec = new PHInstance*[max]; };

    void add(PHInstance* p)
    { vec[num++] = p; };
};

struct FrameworkPolicy
{
    PHInstanceList ilist;

    PHVector packet;
    PHVector network;
    PHVector session;
    PHVector service;
    PHVector probe;

    Inspector* binder;
    Inspector* wizard;

    void vectorize();
};

void FrameworkPolicy::vectorize()
{
    packet.alloc(ilist.size());
    network.alloc(ilist.size());
    session.alloc(ilist.size());
    service.alloc(ilist.size());
    probe.alloc(ilist.size());

    for ( auto* p : ilist )
    {
        switch ( p->pp_class.api.type )
        {
        case IT_PACKET:
            packet.add(p);
            break;

        case IT_NETWORK:
            network.add(p);
            break;

        case IT_STREAM:
            if ( !p->pp_class.api.ssn )
                session.add(p);
            break;

        case IT_SERVICE:
            service.add(p);
            break;

        case IT_BINDER:
            binder = p->handler;
            break;

        case IT_WIZARD:
            wizard = p->handler;
            break;

        case IT_PROBE:
            probe.add(p);
            break;

        case IT_MAX:
            break;
        }
    }
}

//-------------------------------------------------------------------------
// global stuff
//-------------------------------------------------------------------------

void InspectorManager::add_plugin(const InspectApi* api)
{
    PHGlobal* g = new PHGlobal(*api);
    s_handlers.push_back(g);

    if ( api->service )
        AddProtocolReference(api->service);
}

static const InspectApi* get_plugin(const char* keyword)
{
    for ( auto* p : s_handlers )
        if ( !strcmp(p->api.base.name, keyword) )
            return &p->api;

    return nullptr;
}

void InspectorManager::dump_plugins()
{
    Dumper d("Inspectors");

    for ( const auto* p : s_handlers )
        d.dump(p->api.base.name, p->api.base.version);
}

void InspectorManager::dump_buffers()
{
    Dumper d("Inspection Buffers");

    for ( const auto* p : s_handlers )
    {
        const char** b = p->api.buffers;

        while ( b && *b )
        {
            d.dump(p->api.base.name, *b);
            ++b;
        }
    }
}

void InspectorManager::release_plugins ()
{
    empty_trash();

#if 0
    // FIXIT-H multiple policies causes ref_counts > 0
    for ( auto* p : s_trash )
    {
        if ( !p->is_inactive() )
            printf("%s = %u\n", p->get_api()->base.name, p->get_ref(0));
    }
#endif

    for ( auto* p : s_handlers )
    {
        if ( !p->init && p->api.pterm )
            p->api.pterm();

        delete p;
    }
}

void InspectorManager::empty_trash()
{
    while ( !s_trash.empty() )
    {
        auto* p = s_trash.front();

        if ( !p->is_inactive() )
            return;

        free_inspector(p);

        s_trash.pop_front();
    }
}

//-------------------------------------------------------------------------
// policy stuff
//-------------------------------------------------------------------------

void InspectorManager::new_policy (InspectionPolicy* pi)
{
    pi->framework_policy = new FrameworkPolicy;

    pi->framework_policy->binder = nullptr;
    pi->framework_policy->wizard = nullptr;
}

void InspectorManager::delete_policy (InspectionPolicy* pi)
{
    for ( auto* p : pi->framework_policy->ilist )
    {
        s_trash.push_back(p->handler);
        delete p;
    }
    delete pi->framework_policy;
    pi->framework_policy = nullptr;
}

// FIXIT-L allowing lookup by name or type or key is kinda hinky
// would be helpful to have specific lookups
static PHInstance* get_instance(
    FrameworkPolicy* fp, const char* keyword, bool dflt_only = false)
{
    for ( auto* p : fp->ilist )
    {
        if ( p->name.size() && p->name == keyword )
            return p;

        else if ( !strcmp(p->pp_class.api.base.name, keyword) )
            return (!p->name.size() || !dflt_only) ? p : nullptr;

        else if ( p->pp_class.api.service && !strcmp(p->pp_class.api.service, keyword) )
            return p;
    }
    return nullptr;
}

static PHInstance* get_new(
    PHClass* ppc, FrameworkPolicy* fp, const char* keyword)
{
    PHInstance* p = get_instance(fp, keyword);

    if ( p )
        return p;

    p = new PHInstance(*ppc);

    if ( !p->handler )
    {
        delete p;
        return NULL;
    }

    fp->ilist.push_back(p);
    return p;
}

// FIXIT-M create a separate list for meta handlers?  is there really more than one?
void InspectorManager::dispatch_meta (FrameworkPolicy* fp, int type, const uint8_t* data)
{
    for ( auto* p : fp->ilist )
        p->handler->meta(type, data);
}

Inspector* InspectorManager::get_binder()
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    return pi->framework_policy->binder;
} 

Inspector* InspectorManager::get_wizard()
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    return pi->framework_policy->wizard;
} 

// FIXIT-P cache get_inspector() returns or provide indexed lookup
Inspector* InspectorManager::get_inspector(const char* key, bool dflt_only)
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    PHInstance* p = get_instance(pi->framework_policy, key, dflt_only);

    if ( !p )
        return nullptr;

    return p->handler;
} 

InspectorType InspectorManager::get_type(const char* key)
{
    Inspector* p = get_inspector(key);

    if ( !p )
        return IT_MAX;

    return p->get_api()->type;
}

void InspectorManager::free_inspector(Inspector* p)
{
    p->get_api()->dtor(p);
}

InspectSsnFunc InspectorManager::get_session(uint16_t proto)
{
    for ( auto* p : s_handlers )
    {
        if ( p->api.type == IT_STREAM && p->api.proto_bits == proto && !p->init )
            return p->api.ssn;
    }
    return nullptr;
} 

//-------------------------------------------------------------------------
// config stuff
//-------------------------------------------------------------------------

void InspectorManager::new_config (SnortConfig* sc)
{
    sc->framework_config = new FrameworkConfig;
}

void InspectorManager::delete_config (SnortConfig* sc)
{
    for ( auto* p : sc->framework_config->clist )
        delete p;

    delete sc->framework_config;
    sc->framework_config = nullptr;
}

static PHClass* get_class(const char* keyword, FrameworkConfig* fc)
{
    for ( auto* p : fc->clist )
        if ( !strcmp(p->api.base.name, keyword) )
            return p;

    for ( auto* p : s_handlers )
        if ( !strcmp(p->api.base.name, keyword) )
        {
            if ( p->init )
            {
                if ( p->api.pinit )
                    p->api.pinit();
                p->init = false;
            }
            PHClass* ppc = new PHClass(p->api);
            fc->clist.push_back(ppc);
            return ppc;
        }
    return NULL;
}

void InspectorManager::thread_init(SnortConfig* sc)
{
    Inspector::slot = get_instance_id();

    for ( auto* p : sc->framework_config->clist )
    {
        if ( p->api.tinit )
            p->api.tinit();
    }

    // pin->tinit() only called for default policy
    set_default_policy();
    InspectionPolicy* pi = get_inspection_policy();

    if ( pi && pi->framework_policy )
    {
        for ( auto* p : pi->framework_policy->ilist )
            if ( p->pp_class.init )
            {
                p->handler->tinit();
                p->pp_class.init = false;
                p->pp_class.term = true;
            }
    }
}

void InspectorManager::thread_stop(SnortConfig*)
{
    // pin->tterm() only called for default policy
    set_default_policy();
    InspectionPolicy* pi = get_inspection_policy();

    if ( pi && pi->framework_policy )
    {
        for ( auto* p : pi->framework_policy->ilist )
            if ( p->pp_class.term )
            {
                p->handler->tterm();
                p->pp_class.term = false;
                p->pp_class.init = true;
            }
    }
}

void InspectorManager::thread_term(SnortConfig* sc)
{
    for ( auto* p : sc->framework_config->clist )
    {
        if ( p->api.tterm )
            p->api.tterm();
    }
}

//-------------------------------------------------------------------------
// config stuff
//-------------------------------------------------------------------------

// new configuration
void InspectorManager::instantiate(
    const InspectApi* api, Module*, SnortConfig* sc, const char* name)
{
    FrameworkConfig* fc = sc->framework_config;
    FrameworkPolicy* fp = get_inspection_policy()->framework_policy;

    // FIXIT-H should not need to lookup inspector etc
    // since given api and mod
    const char* keyword = api->base.name;

    PHClass* ppc = get_class(keyword, fc);

    if ( !ppc )
        ParseError("unknown inspector: '%s'.", keyword);

    else
    {
        if ( name )
            keyword = name;

        PHInstance* ppi = get_new(ppc, fp, keyword);

        if ( !ppi )
            ParseError("can't instantiate inspector: '%s'.", keyword);

        else if ( name )
            ppi->set_name(name);
    }
}

// create default binding for wizard and configured services
static void instantiate_binder(SnortConfig* sc, FrameworkPolicy* fp)
{
    BinderModule* m = (BinderModule*)ModuleManager::get_module(bind_id);
    bool tcp = false, udp = false;

    for ( unsigned i = 0; i < fp->service.num; i++ )
    {
        const InspectApi& api = fp->service.vec[i]->pp_class.api;

        const char* s = api.service;
        const char* t = api.base.name;
        m->add(s, t);

        tcp = tcp || (api.proto_bits & (unsigned)PktType::TCP);
        udp = udp || (api.proto_bits & (unsigned)PktType::UDP);
    }
    if ( tcp )
        m->add((unsigned)PktType::TCP, wiz_id);

    if ( udp )
        m->add((unsigned)PktType::UDP, wiz_id);

    const InspectApi* api = get_plugin(bind_id);
    InspectorManager::instantiate(api, nullptr, sc);
    fp->binder = get_instance(fp, bind_id)->handler;
    fp->binder->configure(sc);
}

static bool configure(SnortConfig* sc, FrameworkPolicy* fp)
{
    bool ok = true;

    for ( auto* p : fp->ilist )
        ok = p->handler->configure(sc) && ok;

    sort(fp->ilist.begin(), fp->ilist.end(), PHInstance::comp);
    fp->vectorize();

    if ( fp->session.num && !fp->binder )
        instantiate_binder(sc, fp);

    return ok;
}

bool InspectorManager::configure(SnortConfig *sc)
{
    sort(s_handlers.begin(), s_handlers.end(), PHGlobal::comp);
    bool ok = true;

    for ( unsigned idx = 0; idx < sc->policy_map->inspection_policy.size(); ++idx )
    {
        set_policies(sc, idx);
        InspectionPolicy* p = sc->policy_map->inspection_policy[idx];
        ok = ::configure(sc, p->framework_policy) && ok;
    }

    set_policies(sc);
    return ok;
}

void InspectorManager::print_config(SnortConfig *sc)
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi->framework_policy )
        return;

    for ( auto* p : pi->framework_policy->ilist )
        p->handler->show(sc);
}

//-------------------------------------------------------------------------
// packet handling
//-------------------------------------------------------------------------

static inline void execute(
    Packet* p, PHInstance** prep, unsigned num)
{
    for ( unsigned i = 0; i < num; ++i, ++prep )
    {
        if ( p->packet_flags & PKT_PASS_RULE )
            break;

        PHClass& ppc = (*prep)->pp_class;

        // FIXIT-P these checks can eventually be optimized
	    // but they are required to ensure that session and app
	    // handlers aren't called w/o a session pointer
        if ( !p->flow && (ppc.api.type == IT_SERVICE) )
            break;

        if ( ((unsigned)p->type() & ppc.api.proto_bits) )
            (*prep)->handler->eval(p);
    }
}

void InspectorManager::bumble(Packet* p)
{
    Flow* flow = p->flow;
    Inspector* ins = get_binder();

    if ( ins )
        ins->exec(0, flow);

    flow->clear_clouseau();

    if ( !flow->gadget || flow->protocol != PktType::TCP )
        return;

    if ( flow->session )
        flow->session->restart(p);
}

void InspectorManager::full_inspection(FrameworkPolicy* fp, Packet* p)
{
    Flow* flow = p->flow;

    if ( !flow->service )
        ::execute(p, fp->network.vec, fp->network.num);

    else if ( flow->clouseau )
        bumble(p);

    if ( !p->dsize )
        DisableDetect(p);

    // FIXIT-M need list of gadgets for ambiguous wizardry
    else if ( flow->gadget && PacketHasPAFPayload(p) )
        flow->gadget->eval(p);
}

void InspectorManager::execute (Packet* p)
{
    FrameworkPolicy* fp = get_inspection_policy()->framework_policy;
    assert(fp);

    // FIXIT-L blocked flows should not be normalized
    if ( !PacketWasCooked(p) )
        ::execute(p, fp->packet.vec, fp->packet.num);

    if ( !PacketHasPAFPayload(p) )
        ::execute(p, fp->session.vec, fp->session.num);

    Flow* flow = p->flow;

    if ( flow && flow->full_inspection() )
        full_inspection(fp, p);

    ::execute(p, fp->probe.vec, fp->probe.num);
}

