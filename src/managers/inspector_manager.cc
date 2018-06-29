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
// inspector_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "inspector_manager.h"

#include <list>
#include <vector>

#include "binder/bind_module.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "protocols/packet.h"
#include "target_based/snort_protocols.h"

#include "module_manager.h"

using namespace snort;
using namespace std;

// FIXIT-L define module names just once
#define bind_id "binder"
#define wiz_id "wizard"
#define app_id "appid"

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
    { init = true; }

    static bool comp(const PHGlobal* a, const PHGlobal* b)
    { return ( a->api.type < b->api.type ); }
};

struct PHClass
{
    const InspectApi& api;
    bool* init;  // call pin->tinit()
    bool* term;  // call pin->tterm()

    PHClass(const InspectApi& p) : api(p)
    {
        init = new bool[ThreadConfig::get_instance_max()];
        term = new bool[ThreadConfig::get_instance_max()];

        for ( unsigned i = 0; i < ThreadConfig::get_instance_max(); ++i )
            init[i] = term[i] = true;
    }

    ~PHClass()
    {
        delete[] init;
        delete[] term;
    }

    PHClass(const PHClass&) = delete;
    PHClass& operator=(const PHClass&) = delete;

    static bool comp(PHClass* a, PHClass* b)
    { return ( a->api.type < b->api.type ); }
};

enum ReloadType {
    RELOAD_TYPE_NONE = 0,
    RELOAD_TYPE_DELETED,
    RELOAD_TYPE_REENABLED,
    RELOAD_TYPE_NEW,
    RELOAD_TYPE_MAX
};

struct PHInstance
{
    PHClass& pp_class;
    Inspector* handler;
    string name;
    ReloadType reload_type;

    PHInstance(PHClass&, SnortConfig*, Module* = nullptr);
    ~PHInstance();

    static bool comp(PHInstance* a, PHInstance* b)
    { return ( a->pp_class.api.type < b->pp_class.api.type ); }

    void set_name(const char* s)
    { name = s; }

    void set_reloaded(ReloadType val)
    { reload_type = val; }

    bool is_reloaded()
    { return ((reload_type == RELOAD_TYPE_REENABLED) or
            (reload_type == RELOAD_TYPE_DELETED) or
            (reload_type == RELOAD_TYPE_NEW)); }

    ReloadType get_reload_type()
    { return reload_type; }
};

PHInstance::PHInstance(PHClass& p, SnortConfig* sc, Module* mod) : pp_class(p)
{
    reload_type = RELOAD_TYPE_NONE;
    handler = p.api.ctor(mod);

    if ( handler )
    {
        handler->set_api(&p.api);
        handler->add_ref();

        if ( p.api.service )
            handler->set_service(sc->proto_ref->add(p.api.service));
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
static PHList s_trash2;
static THREAD_LOCAL bool s_clear = false;
static bool s_sorted = false;

struct FrameworkConfig
{
    PHClassList clist;
};

struct PHVector
{
    PHInstance** vec;
    unsigned num;

    PHVector()
    { vec = nullptr; num = 0; }

    ~PHVector()
    { if ( vec ) delete[] vec; }

    void alloc(unsigned max)
    { vec = new PHInstance*[max]; }

    void add(PHInstance* p)
    { vec[num++] = p; }

    void add_control(PHInstance*);
};

// FIXIT-L a more sophisticated approach to handling controls etc. may be
// warranted such as a configuration or priority scheme (a la 2X).  for
// now we only require that appid run first among controls.

void PHVector::add_control(PHInstance* p)
{
    const char* name = p->pp_class.api.base.name;

    if ( strcmp(name, app_id) or !num )
        add(p);

    else
    {
        add(vec[0]);
        vec[0] = p;
    }
}

struct FrameworkPolicy
{
    PHInstanceList ilist;

    PHVector passive;
    PHVector packet;
    PHVector network;
    PHVector session;
    PHVector service;
    PHVector control;
    PHVector probe;

    Inspector* binder;
    Inspector* wizard;

    bool default_binder;

    void vectorize(SnortConfig*);
};

void FrameworkPolicy::vectorize(SnortConfig* sc)
{
    passive.alloc(ilist.size());
    packet.alloc(ilist.size());
    network.alloc(ilist.size());
    session.alloc(ilist.size());
    service.alloc(ilist.size());
    control.alloc(ilist.size());
    probe.alloc(ilist.size());

    for ( auto* p : ilist )
    {
        switch ( p->pp_class.api.type )
        {
        case IT_PASSIVE :
            passive.add(p);
            // FIXIT-L Ugly special case for noticing a binder
            if ( !strcmp(p->pp_class.api.base.name, bind_id) )
                binder = p->handler;
            break;

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

        case IT_WIZARD:
            wizard = p->handler;
            break;

        case IT_CONTROL:
            control.add_control(p);
            break;

        case IT_PROBE:
        {
            // probes always run
            // add them to default so they can be found on InspectorManager::probe
            sc->policy_map->get_inspection_policy(0)->framework_policy->probe.add(p);
            break;
        }

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

#if 0
static void dump_refs(PHList& trash)
{
    for ( auto* p : trash )
    {
        if ( !p->is_inactive() )
            printf("%s = %u\n", p->get_api()->base.name, p->get_ref(0));
    }
}

#endif

void InspectorManager::release_plugins()
{
    empty_trash();

#if 0
    dump_refs(s_trash);
    dump_refs(s_trash2);
#endif

    for ( auto* p : s_handlers )
    {
        if ( !p->init && p->api.pterm )
            p->api.pterm();

        delete p;
    }
}

static void empty_trash(PHList& trash)
{
    while ( !trash.empty() )
    {
        auto* p = trash.front();

        if ( !p->is_inactive() )
            return;

        InspectorManager::free_inspector(p);
        trash.pop_front();
    }
}

void InspectorManager::empty_trash()
{
    ::empty_trash(s_trash);
    ::empty_trash(s_trash2);
}

//-------------------------------------------------------------------------
// policy stuff
//-------------------------------------------------------------------------

// FIXIT-L allowing lookup by name or type or key is kinda hinky
// would be helpful to have specific lookups
static bool get_instance(
        FrameworkPolicy* fp, const char* keyword, bool dflt_only, std::vector<PHInstance*>::iterator& it)
{
    for ( it = fp->ilist.begin(); it != fp->ilist.end(); ++it )
    {
        PHInstance* p = *it;
        if ( !p->name.empty() && p->name == keyword )
            return true;

        else if ( !strcmp(p->pp_class.api.base.name, keyword) )
            return (p->name.empty() || !dflt_only) ? true : false;

        else if ( p->pp_class.api.service && !strcmp(p->pp_class.api.service, keyword) )
            return true;
    }
    return false;
}

static PHInstance* get_instance(
        FrameworkPolicy* fp, const char* keyword, bool dflt_only = false)
{
    std::vector<PHInstance*>::iterator it;
    return get_instance(fp, keyword, dflt_only, it) ? *it : nullptr;
}

static PHInstance* get_new(
    PHClass* ppc, FrameworkPolicy* fp, const char* keyword, Module* mod, SnortConfig* sc)
{
    PHInstance* p = nullptr;
    bool reloaded = false;
    std::vector<PHInstance*>::iterator old_it;

    if ( get_instance(fp, keyword, false, old_it) )
    {
        if ( snort::Snort::is_reloading() )
        {
            (*old_it)->set_reloaded(RELOAD_TYPE_REENABLED);
            fp->ilist.erase(old_it);
            reloaded = true;
        }
        else
            return *old_it;
    }

    p = new PHInstance(*ppc, sc, mod);

    if ( !p->handler )
    {
        delete p;
        return nullptr;
    }

    if ( snort::Snort::is_reloading() )
    {
        if ( reloaded )
            p->set_reloaded(RELOAD_TYPE_REENABLED);
        else
            p->set_reloaded(RELOAD_TYPE_NEW);
    }
    fp->ilist.push_back(p);
    return p;
}

void InspectorManager::new_policy(InspectionPolicy* pi, InspectionPolicy* other_pi)
{
    pi->framework_policy = new FrameworkPolicy;
    bool default_binder = false;

    if ( other_pi )
    {
        pi->framework_policy->ilist = other_pi->framework_policy->ilist;
        default_binder = other_pi->framework_policy->default_binder;
    }

    pi->framework_policy->default_binder = default_binder;
    pi->framework_policy->binder = nullptr;
    pi->framework_policy->wizard = nullptr;
}

void InspectorManager::delete_policy(InspectionPolicy* pi, bool cloned)
{
    for ( auto* p : pi->framework_policy->ilist )
    {
        if ( cloned and !(p->is_reloaded()) )
                continue;

        if ( p->handler->get_api()->type == IT_PASSIVE )
            s_trash2.push_back(p->handler);
        else
            s_trash.push_back(p->handler);

        delete p;
    }
    delete pi->framework_policy;
    pi->framework_policy = nullptr;
}

void InspectorManager::update_policy(SnortConfig* sc)
{
    InspectionPolicy* pi = sc->policy_map->get_inspection_policy();
    for ( auto* p : pi->framework_policy->ilist )
        p->set_reloaded(RELOAD_TYPE_NONE);
}
// FIXIT-M create a separate list for meta handlers?  is there really more than one?
void InspectorManager::dispatch_meta(FrameworkPolicy* fp, int type, const uint8_t* data)
{
    for ( auto* p : fp->ilist )
        p->handler->meta(type, data);
}

Binder* InspectorManager::get_binder()
{
    InspectionPolicy* pi = snort::get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    return (Binder*) pi->framework_policy->binder;
}

// FIXIT-P cache get_inspector() returns or provide indexed lookup
Inspector* InspectorManager::get_inspector(const char* key, bool dflt_only)
{
    InspectionPolicy* pi;
    
    if (dflt_only)
        pi = snort::get_default_inspection_policy(SnortConfig::get_conf());
    else
        pi = snort::get_inspection_policy();

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

bool InspectorManager::delete_inspector(SnortConfig* sc, const char* iname)
{
    bool ok = false;
    FrameworkPolicy* fp = sc->policy_map->get_inspection_policy()->framework_policy;
    std::vector<PHInstance*>::iterator old_it;

    if ( get_instance(fp, iname, false, old_it) )
    {
        (*old_it)->set_reloaded(RELOAD_TYPE_DELETED);
        fp->ilist.erase(old_it);
        ok = true;
        std::vector<PHInstance*>::iterator bind_it;
        if ( get_instance(fp, bind_id, false, bind_it) )
        {
            (*bind_it)->handler->remove_inspector_binding(sc, iname);
        }
    }

    return ok;
}

void InspectorManager::free_inspector(Inspector* p)
{
    p->get_api()->dtor(p);
}

InspectSsnFunc InspectorManager::get_session(uint16_t proto)
{
    for ( auto* p : s_handlers )
    {
        if ( p->api.type == IT_STREAM and p->api.proto_bits == proto and !p->init )
            return p->api.ssn;
    }
    return nullptr;
}

//-------------------------------------------------------------------------
// config stuff
//-------------------------------------------------------------------------

void InspectorManager::new_config(SnortConfig* sc)
{
    sc->framework_config = new FrameworkConfig;
}

void InspectorManager::delete_config(SnortConfig* sc)
{
    if ( !sc->framework_config )
        return;

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
    return nullptr;
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
    InspectionPolicy* pi = snort::get_inspection_policy();

    if ( pi && pi->framework_policy )
    {
        unsigned slot = get_instance_id();

        for ( auto* p : pi->framework_policy->ilist )
            if ( p->pp_class.init[slot] )
            {
                p->handler->tinit();
                p->pp_class.init[slot] = false;
                p->pp_class.term[slot] = true;
            }
    }
}

void InspectorManager::thread_stop(SnortConfig*)
{
    // pin->tterm() only called for default policy
    set_default_policy();
    InspectionPolicy* pi = snort::get_inspection_policy();

    if ( pi && pi->framework_policy )
    {
        unsigned slot = get_instance_id();

        for ( auto* p : pi->framework_policy->ilist )
            if ( p->pp_class.term[slot] )
            {
                p->handler->tterm();
                p->pp_class.term[slot] = false;
                p->pp_class.init[slot] = true;
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
    const InspectApi* api, Module* mod, SnortConfig* sc, const char* name)
{
    assert(mod);

    FrameworkConfig* fc = sc->framework_config;
    FrameworkPolicy* fp = snort::get_inspection_policy()->framework_policy;

    // FIXIT-L should not need to lookup inspector etc
    // since given api and mod
    const char* keyword = api->base.name;
    PHClass* ppc = get_class(keyword, fc);

    if ( !ppc )
        ParseError("unknown inspector: '%s'.", keyword);

    else
    {
        if ( name )
            keyword = name;

        PHInstance* ppi = get_new(ppc, fp, keyword, mod, sc);

        if ( !ppi )
            ParseError("can't instantiate inspector: '%s'.", keyword);

        else if ( name )
            ppi->set_name(name);
    }
}

#ifdef PIGLET
// FIXIT-M duplicates logic in void InspectorManager::instantiate()

Inspector* InspectorManager::instantiate(
    const char* name, Module* mod, SnortConfig* sc)
{
    auto ppc = get_class(name, sc->framework_config);

    if ( !ppc )
        return nullptr;

    auto fp = snort::get_inspection_policy()->framework_policy;
    auto ppi = get_new(ppc, fp, name, mod, sc);

    if ( !ppi )
        return nullptr;

    ppi->set_name(name);

    // FIXIT-L can't we just unify PHInstance and InspectorWrapper?
    return ppi->handler;
}
#endif

// create default binding for wizard and configured services
static void instantiate_default_binder(SnortConfig* sc, FrameworkPolicy* fp)
{
    BinderModule* m = (BinderModule*)ModuleManager::get_module(bind_id);
    bool tcp = false, udp = false, pdu = false;

    for ( unsigned i = 0; i < fp->service.num; i++ )
    {
        const InspectApi& api = fp->service.vec[i]->pp_class.api;

        const char* s = api.service;
        const char* t = api.base.name;
        m->add(s, t);

        tcp = tcp or (api.proto_bits & PROTO_BIT__TCP);
        udp = udp or (api.proto_bits & PROTO_BIT__UDP);
        pdu = pdu or (api.proto_bits & PROTO_BIT__PDU);
    }
    if ( tcp or pdu )
        m->add(PROTO_BIT__TCP, wiz_id);

    if ( udp )
        m->add(PROTO_BIT__UDP, wiz_id);

    if ( tcp or udp or pdu )
        m->add(PROTO_BIT__PDU, wiz_id);

    const InspectApi* api = get_plugin(bind_id);
    InspectorManager::instantiate(api, m, sc);
    fp->binder = get_instance(fp, bind_id)->handler;
    fp->binder->configure(sc);
    fp->default_binder = true;
}

static bool configure(SnortConfig* sc, FrameworkPolicy* fp, bool cloned)
{
    bool ok = true;
    bool new_ins = false;
    bool reenabled_ins = false;

    for ( auto* p : fp->ilist )
    {
        ReloadType reload_type = p->get_reload_type();

        if ( cloned )
        {
            if ( reload_type == RELOAD_TYPE_NEW )
                new_ins = true;
            else if ( reload_type == RELOAD_TYPE_REENABLED )
                reenabled_ins = true;
            else
                continue;
        }
        ok = p->handler->configure(sc) && ok;
    }

    if ( new_ins or reenabled_ins )
    {
        std::vector<PHInstance*>::iterator old_binder;
        if ( get_instance(fp, bind_id, false, old_binder) )
        {
            if ( new_ins and fp->default_binder )
            {
                if ( !((*old_binder)->is_reloaded()) )
                {
                    (*old_binder)->set_reloaded(RELOAD_TYPE_REENABLED);
                    fp->ilist.erase(old_binder);
                }
                fp->default_binder = false;
            }
            else if ( reenabled_ins and !((*old_binder)->is_reloaded()) )
            {
                (*old_binder)->handler->configure(sc);
            }
        }
    }

    sort(fp->ilist.begin(), fp->ilist.end(), PHInstance::comp);
    fp->vectorize(sc);

    // FIXIT-M checking for wizard here would avoid fatals for
    // can't bind wizard but this exposes other issues that must
    // be fixed first.
    if ( fp->session.num and !fp->binder /*and fp->wizard*/ )
        instantiate_default_binder(sc, fp);

    return ok;
}

Inspector* InspectorManager::acquire(const char* key, bool dflt_only)
{
    Inspector* pi = get_inspector(key, dflt_only);

    if ( !pi )
        FatalError("unconfigured inspector: '%s'.\n", key);

    else
        pi->add_ref();

    return pi;
}

void InspectorManager::release(Inspector* pi)
{
    assert(pi);
    pi->rem_ref();
}

bool InspectorManager::configure(SnortConfig* sc, bool cloned)
{
    if ( !s_sorted )
    {
        sort(s_handlers.begin(), s_handlers.end(), PHGlobal::comp);
        s_sorted = true;
    }
    bool ok = true;

    for ( unsigned idx = 0; idx < sc->policy_map->inspection_policy_count(); ++idx )
    {
        if ( cloned and idx )
            break;

        set_inspection_policy(sc, idx);
        InspectionPolicy* p = sc->policy_map->get_inspection_policy(idx);
        p->configure();
        ok = ::configure(sc, p->framework_policy, cloned) && ok;
    }

    set_inspection_policy(sc);

    return ok;
}

void InspectorManager::print_config(SnortConfig* sc)
{
    InspectionPolicy* pi = snort::get_inspection_policy();

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

        // FIXIT-L ideally we could eliminate PktType and just use
        // proto_bits but things like teredo need to be fixed up.
        if ( p->type() == PktType::NONE )
        {
            if ( p->proto_bits & ppc.api.proto_bits )
                (*prep)->handler->eval(p);
        }
        else if ( BIT((unsigned)p->type()) & ppc.api.proto_bits )
            (*prep)->handler->eval(p);
    }
}

// FIXIT-L use inspection events instead of exec
void InspectorManager::bumble(Packet* p)
{
    Flow* flow = p->flow;

    DataBus::publish(FLOW_SERVICE_CHANGE_EVENT, p);

    flow->clear_clouseau();

    if ( !flow->gadget || !flow->is_stream() )
        return;

    if ( flow->session )
        flow->session->restart(p);
}

void InspectorManager::full_inspection(Packet* p)
{
    Flow* flow = p->flow;

    if ( flow->service and flow->clouseau and !p->is_cooked() )
        bumble(p);

    if ( !p->dsize )
        DetectionEngine::disable_content(p);

    else if ( flow->gadget && flow->gadget->likes(p) )
    {
        flow->gadget->eval(p);
        s_clear = true;
    }
}

// FIXIT-M leverage knowledge of flow creation so that reputation (possibly a
// new it_xxx) is run just once per flow (and all non-flow packets).

void InspectorManager::execute(Packet* p)
{
    FrameworkPolicy* fp = snort::get_inspection_policy()->framework_policy;
    assert(fp);

    if ( !p->has_paf_payload() )
    {
        // FIXIT-L there is at most one in session; stream_base should
        // be elevated from inspector to framework component (it is just
        // a flow control wrapper) and use eval() instead of process()
        // for stream_*.
        ::execute(p, fp->session.vec, fp->session.num);
        fp = snort::get_inspection_policy()->framework_policy;
    }
    // must check between each ::execute()
    if ( p->disable_inspect )
       return;

    if ( !p->is_cooked() )
        ::execute(p, fp->packet.vec, fp->packet.num);

    if ( p->disable_inspect )
       return;

    SnortConfig* sc = SnortConfig::get_conf();
    FrameworkPolicy* fp_dft = snort::get_default_inspection_policy(sc)->framework_policy;

    if ( !p->flow )
    {
        if (fp_dft != fp)
            ::execute(p, fp_dft->network.vec, fp_dft->network.num);
        ::execute(p, fp->network.vec, fp->network.num);

        if ( p->disable_inspect )
           return;

        ::execute(p, fp_dft->control.vec, fp_dft->control.num);
    }
    else
    {
        if ( !p->has_paf_payload() and p->flow->flow_state == Flow::FlowState::INSPECT )
            p->flow->session->process(p);

        if ( !p->flow->service )
        {
            if (fp_dft != fp)
                ::execute(p, fp_dft->network.vec, fp_dft->network.num);
            ::execute(p, fp->network.vec, fp->network.num);
        }

        if ( p->disable_inspect )
           return;

        if ( p->flow->full_inspection() )
            full_inspection(p);

        if ( !p->disable_inspect and !p->flow->is_inspection_disabled() )
            ::execute(p, fp_dft->control.vec, fp_dft->control.num);
    }
}

void InspectorManager::probe(Packet* p)
{
    InspectionPolicy* policy = snort::SnortConfig::get_conf()->policy_map->get_inspection_policy(0);
    FrameworkPolicy* fp = policy->framework_policy;
    ::execute(p, fp->probe.vec, fp->probe.num);
}

void InspectorManager::clear(Packet* p)
{
    if ( !s_clear )
        return;

    if ( p->flow and p->flow->gadget )
        p->flow->gadget->clear(p);

    s_clear = false;
}

