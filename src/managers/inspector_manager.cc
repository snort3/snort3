//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <cstring>
#include <list>
#include <vector>

#include "binder/bind_module.h"
#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "log/messages.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/snort_module.h"
#include "main/thread_config.h"
#include "search_engines/search_tool.h"
#include "protocols/packet.h"
#include "target_based/snort_protocols.h"
#include "time/clock_defs.h"
#include "time/stopwatch.h"

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
    bool initialized = false;   // In the context of the main thread, this means that api.pinit()
                                // has been called.  In the packet thread, it means that
                                // api.tinit() has been called.
    bool instance_initialized = false;  // In the packet thread, at least one instance has had
                                        // tinit() called.

    PHGlobal(const InspectApi& p) : api(p) { }

    static bool comp(const PHGlobal* a, const PHGlobal* b)
    { return ( a->api.type < b->api.type ); }
};

struct PHClass
{
    const InspectApi& api;

    PHClass(const InspectApi& p) : api(p) { }

    ~PHClass() = default;

    PHClass(const PHClass&) = delete;
    PHClass& operator=(const PHClass&) = delete;

    static bool comp(PHClass* a, PHClass* b)
    { return ( a->api.type < b->api.type ); }
};

enum ReloadType
{
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
    {
        name = s;
        handler->set_alias_name(name.c_str());
    }

    void set_reloaded(ReloadType val)
    { reload_type = val; }

    bool is_reloaded()
    {
        return ((reload_type == RELOAD_TYPE_REENABLED)or
                   (reload_type == RELOAD_TYPE_DELETED) or
                   (reload_type == RELOAD_TYPE_NEW));
    }

    ReloadType get_reload_type()
    { return reload_type; }

    void tinit();
    void tterm();
};

PHInstance::PHInstance(PHClass& p, SnortConfig* sc, Module* mod) : pp_class(p)
{
    reload_type = RELOAD_TYPE_NONE;
    handler = p.api.ctor(mod);

    if ( handler )
    {
        handler->set_api(&p.api);
        handler->add_global_ref();

        if ( p.api.service )
            handler->set_service(sc->proto_ref->add(p.api.service));
    }
}

PHInstance::~PHInstance()
{
    if ( handler )
        handler->rem_global_ref();
}

typedef vector<PHGlobal*> PHGlobalList;
typedef vector<PHClass*> PHClassList;
typedef vector<PHInstance*> PHInstanceList;
typedef list<Inspector*> PHList;

static PHGlobalList s_handlers;
static PHList s_trash;
static PHList s_trash2;
static bool s_sorted = false;

static THREAD_LOCAL vector<PHGlobal>* s_tl_handlers = nullptr;

struct FrameworkConfig
{
    PHClassList clist;  // List of inspector module classes that have been configured
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

struct InspectorList
{
    virtual ~InspectorList() = default;

    PHInstanceList ilist;   // List of inspector module instances
    PHInstanceList removed_ilist;   // List of removed inspector module instances

    virtual void handle_new_reenabled(SnortConfig*, bool, bool) = 0;
    virtual void vectorize(SnortConfig*) = 0;

    void tinit();
    void tterm();
    void tterm_removed();

    void populate_removed(SnortConfig*, InspectorList*);
    void clear_removed();
};

void InspectorList::tinit()
{
    for ( auto* p : ilist )
        p->tinit();
}

void InspectorList::tterm()
{
    for ( auto* p : ilist )
        p->tterm();
}

void InspectorList::tterm_removed()
{
    for ( auto* p : removed_ilist )
        p->tterm();
}

static PHInstance* get_instance(InspectorList* il, const char* keyword);

void InspectorList::populate_removed(SnortConfig* sc, InspectorList* old)
{
    for (auto it = old->ilist.begin(); it != old->ilist.end(); ++it)
    {
        PHInstance* instance = get_instance(this, (*it)->name.c_str());
        if (!instance)
        {
            removed_ilist.emplace_back(*it);
            (*it)->handler->add_global_ref();
            (*it)->handler->tear_down(sc);
        }
    }
}

void InspectorList::clear_removed()
{
    for ( auto* p : removed_ilist )
        p->handler->rem_global_ref();
    removed_ilist.clear();
}

struct TrafficPolicy : public InspectorList
{
    PHVector passive;
    PHVector packet;
    PHVector first;
    PHVector control;

    void handle_new_reenabled(SnortConfig*, bool, bool) override
    { }
    void vectorize(SnortConfig*) override;
};

void TrafficPolicy::vectorize(SnortConfig*)
{
    passive.alloc(ilist.size());
    packet.alloc(ilist.size());
    first.alloc(ilist.size());
    control.alloc(ilist.size());

    for ( auto* p : ilist )
    {
        switch ( p->pp_class.api.type )
        {
        case IT_PASSIVE:
            passive.add(p);
            break;

        case IT_PACKET:
            packet.add(p);
            break;

        case IT_FIRST:
            first.add(p);
            break;

        case IT_CONTROL:
            control.add_control(p);
            break;

        default:
            ParseError(
                "Network policy (context usage) does not handle inspector %s with type %s\n",
                p->pp_class.api.base.name, InspectApi::get_type(p->pp_class.api.type));
            break;
        }
    }
}

class SingleInstanceInspectorPolicy
{
public:
    SingleInstanceInspectorPolicy() = default;
    ~SingleInstanceInspectorPolicy();

    bool get_new(SnortConfig*, Module*, PHClass&, PHInstance*&);
    void populate_removed(SnortConfig*, SingleInstanceInspectorPolicy*);
    void clear_removed();
    void configure(SnortConfig*);
    void tinit();
    void tterm();
    void tterm_removed();
    void print_config(SnortConfig*, const char* title);

    PHInstance* instance = nullptr;
    PHInstance* removed_instance = nullptr;
};

SingleInstanceInspectorPolicy::~SingleInstanceInspectorPolicy()
{
    if (instance)
    {
        if ( IT_PASSIVE == instance->handler->get_api()->type )
            s_trash2.emplace_back(instance->handler);
        else
            s_trash.emplace_back(instance->handler);

        delete instance;
    }
    assert(nullptr == removed_instance);
}

bool SingleInstanceInspectorPolicy::get_new(SnortConfig*sc, Module* mod, PHClass& pc,
    PHInstance*& ppi)
{
    if (instance)
        return false;
    ppi = new PHInstance(pc, sc, mod);
    if ( ppi->handler )
        instance = ppi;
    else
    {
        delete ppi;
        ppi = nullptr;
    }
    return true;
}

void SingleInstanceInspectorPolicy::populate_removed(SnortConfig* sc,
    SingleInstanceInspectorPolicy* old)
{
    if (old->instance && !instance)
    {
        removed_instance = old->instance;
        removed_instance->handler->add_global_ref();
        removed_instance->handler->tear_down(sc);
    }
}

void SingleInstanceInspectorPolicy::clear_removed()
{
    if (removed_instance)
    {
        removed_instance->handler->rem_global_ref();
        removed_instance = nullptr;
    }
}

void SingleInstanceInspectorPolicy::configure(SnortConfig* sc)
{
    if (instance)
        instance->handler->configure(sc);
}

void SingleInstanceInspectorPolicy::tinit()
{
    if (instance)
        instance->tinit();
}

void SingleInstanceInspectorPolicy::tterm()
{
    if (instance)
        instance->tterm();
}

void SingleInstanceInspectorPolicy::tterm_removed()
{
    if (removed_instance)
        removed_instance->tterm();
}

void SingleInstanceInspectorPolicy::print_config(SnortConfig* sc, const char* title)
{
    if (instance)
    {
        LogLabel(title);
        const std::string name = InspectorManager::generate_inspector_label(instance);
        LogLabel(name.c_str());
        instance->handler->show(sc);
    }
}

struct GlobalInspectorPolicy : public InspectorList
{
    PHVector passive;
    PHVector probe;

    void handle_new_reenabled(SnortConfig*, bool, bool) override
    { }
    void vectorize(SnortConfig*) override;
};

void GlobalInspectorPolicy::vectorize(SnortConfig*)
{
    passive.alloc(ilist.size());
    probe.alloc(ilist.size());
    for ( auto* p : ilist )
    {
        switch ( p->pp_class.api.type )
        {
        case IT_PASSIVE:
            passive.add(p);
            break;

        case IT_PROBE:
            probe.add(p);
            break;

        default:
            ParseError(
                "Global inspector policy (global usage) does not handle inspector %s with type %s\n",
                p->pp_class.api.base.name, InspectApi::get_type(p->pp_class.api.type));
            break;
        }
    }
}

struct FrameworkPolicy : public InspectorList
{
    PHVector passive;
    PHVector packet;
    PHVector network;
    PHVector service;

    Inspector* binder;
    Inspector* wizard;

    std::unordered_map<SnortProtocolId, Inspector*> inspector_cache_by_id;
    std::unordered_map<std::string, Inspector*> inspector_cache_by_service;

    bool default_binder;

    void handle_new_reenabled(SnortConfig*, bool, bool) override;
    void vectorize(SnortConfig*) override;
    void add_inspector_to_cache(PHInstance*, SnortConfig*);
    void remove_inspector_from_cache(Inspector*);
    bool delete_inspector(SnortConfig*, const char* iname);
};

void FrameworkPolicy::add_inspector_to_cache(PHInstance* p, SnortConfig* sc)
{
    if (p->pp_class.api.type == IT_SERVICE and p->pp_class.api.service and p->handler)
    {
        SnortProtocolId id = sc->proto_ref->find(p->pp_class.api.service);
        if (id != UNKNOWN_PROTOCOL_ID)
            inspector_cache_by_id[id] = p->handler;
        inspector_cache_by_service[p->pp_class.api.service] = p->handler;
    }
}

void FrameworkPolicy::remove_inspector_from_cache(Inspector* ins)
{
    if (!ins)
        return;

    for(auto i = inspector_cache_by_id.begin(); i != inspector_cache_by_id.end(); i++)
    {
        if (ins == i->second)
        {
            inspector_cache_by_id.erase(i);
            break;
        }
    }
    for(auto i = inspector_cache_by_service.begin(); i != inspector_cache_by_service.end(); i++)
    {
        if (ins == i->second)
        {
            inspector_cache_by_service.erase(i);
            break;
        }
    }
}

static bool get_instance(InspectorList*, const char*,
    std::vector<PHInstance*>::iterator&);

void FrameworkPolicy::handle_new_reenabled(SnortConfig* sc, bool new_ins, bool reenabled_ins)
{
    std::vector<PHInstance*>::iterator old_binder;
    if ( get_instance(this, bind_id, old_binder) )
    {
        if ( new_ins and default_binder )
        {
            if ( !((*old_binder)->is_reloaded()) )
            {
                (*old_binder)->set_reloaded(RELOAD_TYPE_REENABLED);
                ilist.erase(old_binder);
            }
            default_binder = false;
        }
        else if ( reenabled_ins and !((*old_binder)->is_reloaded()) )
        {
            (*old_binder)->handler->configure(sc);
        }
    }
}

static void instantiate_default_binder(SnortConfig*, FrameworkPolicy*);

void FrameworkPolicy::vectorize(SnortConfig* sc)
{
    passive.alloc(ilist.size());
    packet.alloc(ilist.size());
    network.alloc(ilist.size());
    service.alloc(ilist.size());

    for ( auto* p : ilist )
    {
        switch ( p->pp_class.api.type )
        {
        case IT_PASSIVE:
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
            break;

        case IT_SERVICE:
            service.add(p);
            break;

        case IT_WIZARD:
            wizard = p->handler;
            break;

        default:
            ParseError("Inspection policy does not handle inspector %s with type %s\n",
                p->pp_class.api.base.name, InspectApi::get_type(p->pp_class.api.type));
            break;
        }
    }

    // create cache
    inspector_cache_by_id.clear();
    inspector_cache_by_service.clear();
    for ( auto* p : ilist )
        add_inspector_to_cache(p, sc);

    if ( !binder and (sc->policy_map->get_flow_tracking()->instance or wizard) )
        instantiate_default_binder(sc, this);
}

bool FrameworkPolicy::delete_inspector(SnortConfig* sc, const char* iname)
{
    std::vector<PHInstance*>::iterator old_it;
    if ( get_instance(this, iname, old_it) )
    {
        (*old_it)->set_reloaded(RELOAD_TYPE_DELETED);
        remove_inspector_from_cache((*old_it)->handler);
        ilist.erase(old_it);
        std::vector<PHInstance*>::iterator bind_it;
        if ( get_instance(this, bind_id, bind_it) )
            (*bind_it)->handler->remove_inspector_binding(sc, iname);
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// global stuff
//-------------------------------------------------------------------------

std::vector<const InspectApi*> InspectorManager::get_apis()
{
    std::vector<const InspectApi*> v;

    for ( const auto* p : s_handlers )
        v.emplace_back(&p->api);

    return v;
}

const char* InspectorManager::get_inspector_type(const char* name)
{
    for ( const auto* p : s_handlers )
        if ( !strcmp(p->api.base.name, name) )
            return p->api.get_type(p->api.type);

    return "";
}

void InspectorManager::add_plugin(const InspectApi* api)
{
    PHGlobal* g = new PHGlobal(*api);
    s_handlers.emplace_back(g);
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

static void purge_trash(const PHList& trash)
{
    for ( auto* p : trash )
        if ( p->is_inactive() )
            InspectorManager::free_inspector(p);
        else
            WarningMessage("Inspector found in the trash is still in use: '%s'.\n",
                p->get_api()->base.name);
}

void InspectorManager::release_plugins()
{
    purge_trash(s_trash);
    purge_trash(s_trash2);

    for ( auto* p : s_handlers )
    {
        if ( p->initialized && p->api.pterm )
            p->api.pterm();

        delete p;
    }
}

static void empty_trash(PHList& trash)
{
    while ( !trash.empty() )
    {
        auto* p = trash.front();
        trash.pop_front();

        if ( !p->is_inactive() )
        {
            trash.emplace_back(p);
            return;
        }

        InspectorManager::free_inspector(p);
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

SingleInstanceInspectorPolicy* InspectorManager::create_single_instance_inspector_policy()
{ return new SingleInstanceInspectorPolicy; }

void InspectorManager::destroy_single_instance_inspector(SingleInstanceInspectorPolicy* p)
{ delete p; }

GlobalInspectorPolicy* InspectorManager::create_global_inspector_policy(GlobalInspectorPolicy* other_pp)
{
    GlobalInspectorPolicy* pp = new GlobalInspectorPolicy;

    if ( other_pp )
        pp->ilist = other_pp->ilist;

    return pp;
}

void InspectorManager::destroy_global_inspector_policy(GlobalInspectorPolicy* pp, bool cloned)
{
    for ( auto* p : pp->ilist )
    {
        if ( cloned and !(p->is_reloaded()) )
            continue;
        if ( IT_PASSIVE == p->handler->get_api()->type )
            s_trash2.emplace_back(p->handler);
        else
            s_trash.emplace_back(p->handler);
        delete p;
    }
    delete pp;
}

static bool get_instance(InspectorList* il, const char* keyword,
    std::vector<PHInstance*>::iterator& it)
{
    for ( it = il->ilist.begin(); it != il->ilist.end(); ++it )
    {
        if ( (*it)->name == keyword )
            return true;
    }
    return false;
}

static PHInstance* get_instance(InspectorList* il, const char* keyword)
{
    std::vector<PHInstance*>::iterator it;
    return get_instance(il, keyword, it) ? *it : nullptr;
}

static PHInstance* get_new(
    PHClass* ppc, InspectorList* il, const char* keyword, Module* mod, SnortConfig* sc)
{
    PHInstance* p = nullptr;
    bool reloaded = false;
    std::vector<PHInstance*>::iterator old_it;

    if ( get_instance(il, keyword, old_it) )
    {
        if ( Snort::is_reloading() )
        {
            (*old_it)->set_reloaded(RELOAD_TYPE_REENABLED);
            il->ilist.erase(old_it);
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

    if ( Snort::is_reloading() )
    {
        if ( reloaded )
            p->set_reloaded(RELOAD_TYPE_REENABLED);
        else
            p->set_reloaded(RELOAD_TYPE_NEW);
    }
    il->ilist.emplace_back(p);
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

void InspectorManager::new_policy(NetworkPolicy* pi, NetworkPolicy* other_pi)
{
    pi->traffic_policy = new TrafficPolicy;

    if ( other_pi )
        pi->traffic_policy->ilist = other_pi->traffic_policy->ilist;
}

void InspectorManager::delete_policy(InspectionPolicy* pi, bool cloned)
{
    for ( auto* p : pi->framework_policy->ilist )
    {
        if ( cloned and !(p->is_reloaded()) )
            continue;

        if ( p->handler->get_api()->type == IT_PASSIVE )
            s_trash2.emplace_back(p->handler);
        else
            s_trash.emplace_back(p->handler);

        delete p;
    }
    delete pi->framework_policy;
    pi->framework_policy = nullptr;
}

void InspectorManager::delete_policy(NetworkPolicy* pi, bool cloned)
{
    for ( auto* p : pi->traffic_policy->ilist )
    {
        if ( cloned and !(p->is_reloaded()) )
            continue;

        if ( p->handler->get_api()->type == IT_PASSIVE )
            s_trash2.emplace_back(p->handler);
        else
            s_trash.emplace_back(p->handler);

        delete p;
    }
    delete pi->traffic_policy;
    pi->traffic_policy = nullptr;
}

void InspectorManager::update_policy(SnortConfig* sc)
{
    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    for ( auto* p : pp->ilist )
        p->set_reloaded(RELOAD_TYPE_NONE);
    InspectionPolicy* ip = sc->policy_map->get_inspection_policy();
    for ( auto* p : ip->framework_policy->ilist )
        p->set_reloaded(RELOAD_TYPE_NONE);
    NetworkPolicy* np = sc->policy_map->get_network_policy();
    for ( auto* p : np->traffic_policy->ilist )
        p->set_reloaded(RELOAD_TYPE_NONE);
}

Binder* InspectorManager::get_binder()
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    return (Binder*)pi->framework_policy->binder;
}

void InspectorManager::clear_removed_inspectors(SnortConfig* sc)
{
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->clear_removed();
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->clear_removed();
    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    pp->clear_removed();
    TrafficPolicy* tp = sc->policy_map->get_network_policy()->traffic_policy;
    tp->clear_removed();
    FrameworkPolicy* fp = sc->policy_map->get_inspection_policy()->framework_policy;
    fp->clear_removed();
}

void InspectorManager::tear_down_removed_inspectors(const SnortConfig* old, SnortConfig* sc)
{
    SingleInstanceInspectorPolicy* old_fid = old->policy_map->get_file_id();
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->populate_removed(sc, old_fid);

    SingleInstanceInspectorPolicy* old_ft = old->policy_map->get_flow_tracking();
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->populate_removed(sc, old_ft);

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    GlobalInspectorPolicy* old_pp = old->policy_map->get_global_inspector_policy();
    pp->populate_removed(sc, old_pp);

    TrafficPolicy* tp = get_default_network_policy(sc)->traffic_policy;
    TrafficPolicy* old_tp = get_default_network_policy(old)->traffic_policy;
    tp->populate_removed(sc, old_tp);

    FrameworkPolicy* fp = get_default_inspection_policy(sc)->framework_policy;
    FrameworkPolicy* old_fp = get_default_inspection_policy(old)->framework_policy;
    fp->populate_removed(sc, old_fp);
}

Inspector* InspectorManager::get_file_inspector(const SnortConfig* sc)
{
    if ( !sc )
        sc = SnortConfig::get_conf();
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    return fid->instance ? fid->instance->handler : nullptr;
}

// FIXIT-P cache get_inspector() returns or provide indexed lookup
Inspector* InspectorManager::get_inspector(const char* key, bool dflt_only, const SnortConfig* sc)
{
    InspectionPolicy* pi;
    NetworkPolicy* ni;

    if ( !sc )
        sc = SnortConfig::get_conf();
    if ( dflt_only )
    {
        pi = get_default_inspection_policy(sc);
        ni = get_default_network_policy(sc);
    }
    else
    {
        pi = get_inspection_policy();
        ni = get_network_policy();
    }

    if ( pi && pi->framework_policy )
    {
        PHInstance* p = get_instance(pi->framework_policy, key);
        if ( p )
            return p->handler;
    }

    if ( ni && ni->traffic_policy )
    {
        PHInstance* p = get_instance(ni->traffic_policy, key);
        if ( p )
            return p->handler;
    }

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    PHInstance* p = get_instance(pp, key);
    if ( p )
        return p->handler;

    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    if ( ft->instance && ft->instance->name == key )
        return ft->instance->handler;

    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    if ( fid->instance && fid->instance->name == key )
        return fid->instance->handler;

    return nullptr;
}

Inspector* InspectorManager::get_service_inspector_by_service(const char* key)
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    auto g = pi->framework_policy->inspector_cache_by_service.find(key);
    return (g != pi->framework_policy->inspector_cache_by_service.end()) ? g->second : nullptr;
}

Inspector* InspectorManager::get_service_inspector_by_id(const SnortProtocolId protocol_id)
{
    InspectionPolicy* pi = get_inspection_policy();

    if ( !pi || !pi->framework_policy )
        return nullptr;

    auto g = pi->framework_policy->inspector_cache_by_id.find(protocol_id);
    return (g != pi->framework_policy->inspector_cache_by_id.end()) ? g->second : nullptr;
}

bool InspectorManager::delete_inspector(SnortConfig* sc, const char* iname)
{
    FrameworkPolicy* fp = sc->policy_map->get_inspection_policy()->framework_policy;
    return fp->delete_inspector(sc, iname);
}

void InspectorManager::free_inspector(Inspector* p)
{
    p->get_api()->dtor(p);
}

InspectSsnFunc InspectorManager::get_session(uint16_t proto)
{
    for ( auto* p : s_handlers )
    {
        if ( p->api.type == IT_STREAM && p->api.proto_bits == proto && p->initialized )
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
            if ( !p->initialized )
            {
                if ( p->api.pinit )
                    p->api.pinit();
                p->initialized = true;
            }
            PHClass* ppc = new PHClass(p->api);
            fc->clist.emplace_back(ppc);
            return ppc;
        }
    return nullptr;
}

static PHGlobal& get_thread_local_plugin(const InspectApi& api)
{
    assert(s_tl_handlers != nullptr);

    for ( PHGlobal& phg : *s_tl_handlers )
    {
        if ( &phg.api == &api )
            return phg;
    }
    s_tl_handlers->emplace_back(api);
    return s_tl_handlers->back();
}

void PHInstance::tinit()
{
    PHGlobal& phg = get_thread_local_plugin(pp_class.api);
    if ( !phg.instance_initialized )
    {
        handler->tinit();
        phg.instance_initialized = true;
    }
}

void PHInstance::tterm()
{
    PHGlobal& phg = get_thread_local_plugin(pp_class.api);
    if ( phg.instance_initialized )
    {
        handler->tterm();
        phg.instance_initialized = false;
    }
}

void InspectorManager::thread_init(const SnortConfig* sc)
{
    Inspector::slot = get_instance_id();

    // Initial build out of this thread's configured plugin registry
    s_tl_handlers = new vector<PHGlobal>;
    for ( auto* p : sc->framework_config->clist )
    {
        PHGlobal& phg = get_thread_local_plugin(p->api);
        if (phg.api.tinit)
            phg.api.tinit();
        phg.initialized = true;
    }

    // pin->tinit() only called for default policy
    set_default_policy(sc);
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->tinit();
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->tinit();

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    pp->tinit();

    InspectionPolicy* pi = get_inspection_policy();
    if ( pi && pi->framework_policy )
        pi->framework_policy->tinit();

    for ( unsigned i = 0; i < sc->policy_map->network_policy_count(); i++)
    {
        NetworkPolicy* npi = sc->policy_map->get_network_policy(i);
        set_network_policy(npi);
        npi->traffic_policy->tinit();
    }
}

void InspectorManager::thread_reinit(const SnortConfig* sc)
{
    // Update this thread's configured plugin registry with any newly configured inspectors
    for ( auto* p : sc->framework_config->clist )
    {
        PHGlobal& phg = get_thread_local_plugin(p->api);
        if (!phg.initialized)
        {
            if (phg.api.tinit)
                phg.api.tinit();
            phg.initialized = true;
        }
    }

    set_default_policy(sc);
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->tinit();
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->tinit();

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    pp->tinit();

    for ( unsigned i = 0; i < sc->policy_map->network_policy_count(); i++)
    {
        NetworkPolicy* npi = sc->policy_map->get_network_policy(i);
        set_network_policy(npi);
        npi->traffic_policy->tinit();

        // pin->tinit() only called for default policy
        InspectionPolicy* pi = get_default_inspection_policy(sc);
        if ( pi && pi->framework_policy )
            pi->framework_policy->tinit();
    }
}

void InspectorManager::thread_stop_removed(const SnortConfig* sc)
{
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->tterm_removed();

    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->tterm_removed();

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    pp->tterm_removed();

    // pin->tinit() only called for default policy
    NetworkPolicy* npi = get_default_network_policy(sc);
    if ( npi && npi->traffic_policy )
    {
        // Call pin->tterm() for anything that has been initialized and removed
        npi->traffic_policy->tterm_removed();
    }

    // pin->tinit() only called for default policy
    InspectionPolicy* pi = get_default_inspection_policy(sc);

    if ( pi && pi->framework_policy )
    {
        // Call pin->tterm() for anything that has been initialized and removed
        pi->framework_policy->tterm_removed();
    }
}

void InspectorManager::thread_stop(const SnortConfig* sc)
{
    // If thread_init() was never called, we have nothing to do.
    if ( !s_tl_handlers )
        return;

    set_default_policy(sc);
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->tterm();
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->tterm();

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    pp->tterm();

    InspectionPolicy* pi = get_inspection_policy();
    if ( pi && pi->framework_policy )
        pi->framework_policy->tterm();

    for ( unsigned i = 0; i < sc->policy_map->network_policy_count(); i++)
    {
        NetworkPolicy* npi = sc->policy_map->get_network_policy(i);
        set_network_policy(npi);
        npi->traffic_policy->tterm();
    }
}

void InspectorManager::thread_term()
{
    // If thread_init() was never called, we have nothing to do.
    if ( !s_tl_handlers )
        return;

    // Call tterm for every inspector plugin ever configured during the lifetime of this thread
    for ( PHGlobal& phg : *s_tl_handlers )
    {
        if ( phg.api.tterm && phg.initialized )
            phg.api.tterm();
    }
    delete s_tl_handlers;
    s_tl_handlers = nullptr;
}

//-------------------------------------------------------------------------
// config stuff
//-------------------------------------------------------------------------

// new configuration
void InspectorManager::instantiate(
    const InspectApi* api, Module* mod, SnortConfig* sc, const char* name)
{
    assert(mod);

    // FIXIT-L should not need to lookup inspector etc
    // since given api and mod
    FrameworkConfig* fc = sc->framework_config;
    const char* keyword = api->base.name;
    PHClass* ppc = get_class(keyword, fc);

    if ( !ppc )
        ParseError("unknown inspector: '%s'.", keyword);
    else
    {
        PHInstance* ppi;
        if (Module::GLOBAL == mod->get_usage() && IT_FILE == api->type)
        {
            SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
            assert(fid);
            if (!fid->get_new(sc, mod, *ppc, ppi))
            {
                ParseError("Only one file identification inspector may be instantiated\n");
                return;
            }
        }
        else if (Module::GLOBAL == mod->get_usage() && IT_STREAM == api->type)
        {
            SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
            assert(ft);
            if (!ft->get_new(sc, mod, *ppc, ppi))
            {
                ParseError("Only one flow tracking inspector may be instantiated\n");
                return;
            }
        }
        else
        {
            if ( name )
                keyword = name;
            if (Module::GLOBAL == mod->get_usage() && IT_SERVICE != api->type)
            {
                GlobalInspectorPolicy* il = sc->policy_map->get_global_inspector_policy();
                assert(il);
                ppi = get_new(ppc, il, keyword, mod, sc);
            }
            else if (Module::CONTEXT == mod->get_usage())
            {
                TrafficPolicy* il = get_network_policy()->traffic_policy;
                assert(il);
                ppi = get_new(ppc, il, keyword, mod, sc);
            }
            else
            {
                FrameworkPolicy* il = get_inspection_policy()->framework_policy;
                assert(il);
                ppi = get_new(ppc, il, keyword, mod, sc);
            }
        }

        if ( ppi )
            ppi->set_name(keyword);
        else
            ParseError("can't instantiate inspector: '%s'.", keyword);
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

    auto fp = get_inspection_policy()->framework_policy;
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
        m->add(PROTO_BIT__USER, wiz_id);

    const InspectApi* api = get_plugin(bind_id);
    InspectorManager::instantiate(api, m, sc);
    fp->binder = get_instance(fp, bind_id)->handler;
    fp->binder->configure(sc);
    fp->default_binder = true;
}

static bool configure(SnortConfig* sc, InspectorList* il, bool cloned, bool& new_ins,
    bool& reenabled_ins)
{
    bool ok = true;

    for ( auto* p : il->ilist )
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
        il->handle_new_reenabled(sc, new_ins, reenabled_ins);

    sort(il->ilist.begin(), il->ilist.end(), PHInstance::comp);
    il->vectorize(sc);

    return ok;
}

Inspector* InspectorManager::acquire_file_inspector()
{
    Inspector* pi = get_file_inspector();

    if ( !pi )
        FatalError("unconfigured file inspector\n");
    else
        pi->add_global_ref();

    return pi;
}

Inspector* InspectorManager::acquire(const char* key, bool dflt_only)
{
    Inspector* pi = get_inspector(key, dflt_only);

    if ( !pi )
        FatalError("unconfigured inspector: '%s'.\n", key);
    else
        pi->add_global_ref();

    return pi;
}

void InspectorManager::release(Inspector* pi)
{
    assert(pi);
    pi->rem_global_ref();
}

bool InspectorManager::configure(SnortConfig* sc, bool cloned)
{
    if ( !s_sorted )
    {
        sort(s_handlers.begin(), s_handlers.end(), PHGlobal::comp);
        s_sorted = true;
    }
    bool ok = true;

    SearchTool::set_conf(sc);

    bool new_ins = false;
    bool reenabled_ins = false;
    for ( unsigned idx = 0; idx < sc->policy_map->network_policy_count(); ++idx )
    {
        if ( cloned and idx )
            break;

        ::set_network_policy(sc, idx);
        NetworkPolicy* p = sc->policy_map->get_network_policy(idx);
        ok = ::configure(sc, p->traffic_policy, cloned, new_ins, reenabled_ins) && ok;
    }
    ::set_network_policy(sc);

    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->configure(sc);

    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->configure(sc);

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    ok = ::configure(sc, pp, cloned, new_ins, reenabled_ins) && ok;

    ::set_inspection_policy(sc);
    for ( unsigned idx = 0; idx < sc->policy_map->inspection_policy_count(); ++idx )
    {
        if ( cloned and idx )
            break;

        ::set_inspection_policy(sc, idx);
        InspectionPolicy* p = sc->policy_map->get_inspection_policy(idx);
        p->configure();
        ok = ::configure(sc, p->framework_policy, cloned, new_ins, reenabled_ins) && ok;
    }

    ::set_inspection_policy(sc);
    SearchTool::set_conf(nullptr);

    return ok;
}

// remove any disabled controls while retaining order
void InspectorManager::prepare_controls(SnortConfig* sc)
{
    for ( unsigned idx = 0; idx < sc->policy_map->network_policy_count(); ++idx )
    {
        TrafficPolicy* tp = sc->policy_map->get_network_policy(idx)->traffic_policy;
        unsigned c = 0;
        for ( unsigned i = 0; i < tp->control.num; ++i )
        {
            if ( !tp->control.vec[i]->handler->disable(sc) )
                tp->control.vec[c++] = tp->control.vec[i];
        }
        tp->control.num = c;
    }
}

std::string InspectorManager::generate_inspector_label(const PHInstance* p)
{
    std::string name(p->pp_class.api.base.name);
    if ( p->name != name )
        name += " (" + p->name + "):";
    else
        name += ":";
    return name;
}

void InspectorManager::sort_inspector_list(const InspectorList* il,
    std::map<const std::string, const PHInstance*>& sorted_ilist)
{
    for ( const auto* p : il->ilist )
    {
        std::string name = generate_inspector_label(p);
        sorted_ilist.emplace(name, p);
    }
}

void InspectorManager::print_config(SnortConfig* sc)
{
    SingleInstanceInspectorPolicy* fid = sc->policy_map->get_file_id();
    fid->print_config(sc, "File Identification");
    SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
    ft->print_config(sc, "Flow Tracking");

    GlobalInspectorPolicy* pp = sc->policy_map->get_global_inspector_policy();
    if (!pp->ilist.empty())
    {
        LogLabel("Global Inspectors");
        std::map<const std::string, const PHInstance*> pp_sorted_ilist;
        sort_inspector_list(pp, pp_sorted_ilist);
        for ( const auto& p : pp_sorted_ilist )
        {
            LogLabel(p.first.c_str());
            p.second->handler->show(sc);
        }
    }

    const auto shell_number = sc->policy_map->shells_count();

    for ( unsigned shell_id = 0; shell_id < shell_number; shell_id++ )
    {
        const auto shell = sc->policy_map->get_shell(shell_id);
        const auto policies = sc->policy_map->get_policies(shell);

        const auto network = policies->network;
        if ( network and network->traffic_policy )
        {
            const std::string label = "Network Policy : policy id " +
                std::to_string(network->user_policy_id) + " : " +
                shell->get_file();
            LogLabel(label.c_str());
            std::map<const std::string, const PHInstance*> sorted_ilist;
            sort_inspector_list(network->traffic_policy, sorted_ilist);
            for ( const auto& p : sorted_ilist )
            {
                LogLabel(p.first.c_str());
                p.second->handler->show(sc);
            }
        }

        const auto inspection = policies->inspection;
        if ( inspection and inspection->framework_policy )
        {
            const std::string label = "Inspection Policy : policy id " +
                std::to_string(inspection->user_policy_id) + " : " +
                shell->get_file();
            LogLabel(label.c_str());
            std::map<const std::string, const PHInstance*> sorted_ilist;
            sort_inspector_list(inspection->framework_policy, sorted_ilist);
            for ( const auto& p : sorted_ilist )
            {
                LogLabel(p.first.c_str());
                p.second->handler->show(sc);
            }
        }
    }
}

//-------------------------------------------------------------------------
// packet handling
//-------------------------------------------------------------------------

template<bool T>
static inline void execute(
    Packet* p, PHInstance* const * prep, unsigned num, bool probe = false)
{
    Stopwatch<SnortClock> timer;
    for ( unsigned i = 0; i < num; ++i, ++prep )
    {
        if ( p->packet_flags & PKT_PASS_RULE )
            break;

        const PHClass& ppc = (*prep)->pp_class;

        // FIXIT-P these checks can eventually be optimized
        // but they are required to ensure that session and app
        // handlers aren't called w/o a session pointer
        if ( !p->flow && (ppc.api.type == IT_SERVICE) )
            break;

        const char* inspector_name = nullptr;
        if ( T )
        {
            timer.reset();
            inspector_name = (*prep)->name.c_str();
            trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p, "enter %s\n", inspector_name);
            timer.start();
        }

        // FIXIT-L ideally we could eliminate PktType and just use
        // proto_bits but things like teredo need to be fixed up.
        if ( p->type() == PktType::NONE )
        {
            if ( p->proto_bits & ppc.api.proto_bits )
                (*prep)->handler->eval(p);
        }
        else if ( BIT((unsigned)p->type()) & ppc.api.proto_bits )
            (*prep)->handler->eval(p);

        if ( T )
            trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
                "exit %s, elapsed time: %" PRId64" usec\n", inspector_name, TO_USECS(timer.get()));

        // must check between each ::execute()
        if ( !probe && p->disable_inspect )
            return;
    }
}

void InspectorManager::bumble(Packet* p)
{
    Flow* flow = p->flow;

    DataBus::publish(FLOW_SERVICE_CHANGE_EVENT, p);

    flow->clear_clouseau();

    if ( !flow->gadget )
    {
        if ( !flow->flags.svc_event_generated )
        {
            DataBus::publish(FLOW_NO_SERVICE_EVENT, p);
            flow->flags.svc_event_generated = true;
        }

        return;
    }

    if ( !flow->is_stream() )
        return;

    if ( flow->session )
        flow->session->restart(p);
}

template<bool T>
void InspectorManager::full_inspection(Packet* p)
{
    Flow* flow = p->flow;

    if ( flow->service and flow->clouseau and (!(p->is_cooked()) or p->is_defrag()) )
        bumble(p);

    // For reassembled PDUs, a null data buffer signals no detection. Detection can be required
    // with a length of 0. For raw packets, a length of 0 does signal no detection.
    if ( (p->is_cooked() and !p->data) or (!p->is_cooked() and !p->dsize) )
        DetectionEngine::disable_content(p);

    else if ( flow->gadget && flow->gadget->likes(p) )
    {
        if ( !T )
            flow->gadget->eval(p);
        else
        {
            Stopwatch<SnortClock> timer;
            const char* inspector_name = flow->gadget->get_alias_name();
            trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p, "enter %s\n", inspector_name);
            timer.start();

            flow->gadget->eval(p);

            trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
                "exit %s, elapsed time: %" PRId64 "\n", inspector_name, TO_USECS(timer.get()));
        }

        p->context->clear_inspectors = true;
    }
}

// FIXIT-M leverage knowledge of flow creation so that reputation (possibly a
// new it_xxx) is run just once per flow (and all non-flow packets).
void InspectorManager::execute(Packet* p)
{
    if ( trace_enabled(snort_trace, TRACE_INSPECTOR_MANAGER, DEFAULT_TRACE_LOG_LEVEL, p) )
        internal_execute<true>(p);
    else
        internal_execute<false>(p);
}

template<bool T>
void InspectorManager::internal_execute(Packet* p)
{
    Stopwatch<SnortClock> timer;
    const char* packet_type = nullptr;
    if ( T )
    {
        packet_type = p->is_rebuilt() ? "rebuilt" : "raw";

        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "start inspection, %s, packet %" PRId64", context %" PRId64"\n",
            packet_type, p->context->packet_number, p->context->context_num);

        timer.start();
    }

    const SnortConfig* sc = p->context->conf;
    if ( !p->has_paf_payload() )
    {
        SingleInstanceInspectorPolicy* ft = sc->policy_map->get_flow_tracking();
        if (ft->instance )
            ::execute<T>(p, &ft->instance, 1);
    }

    // must check between each ::execute()
    if ( p->disable_inspect )
        return;

    if (!p->flow)
        DataBus::publish(PKT_WITHOUT_FLOW_EVENT, p);

    FrameworkPolicy* fp = get_inspection_policy()->framework_policy;
    assert(fp);

    if ( !p->is_cooked() )
        ::execute<T>(p, fp->packet.vec, fp->packet.num);

    if ( p->disable_inspect )
        return;

    TrafficPolicy* tp = get_network_policy()->traffic_policy;
    assert(tp);

    if ( !p->is_cooked() )
        ::execute<T>(p, tp->packet.vec, tp->packet.num);

    if ( p->disable_inspect )
        return;

    if ( !p->flow )
    {
        ::execute<T>(p, tp->first.vec, tp->first.num);

        if ( p->disable_inspect )
            return;

        ::execute<T>(p, fp->network.vec, fp->network.num);

        if ( p->disable_inspect )
            return;

        ::execute<T>(p, tp->control.vec, tp->control.num);
    }
    else
    {
        if ( !p->has_paf_payload() and p->flow->flow_state == Flow::FlowState::INSPECT )
            p->flow->session->process(p);

        if ( p->flow->reload_id != sc->reload_id )
        {
            ::execute<T>(p, tp->first.vec, tp->first.num);

            p->flow->reload_id = sc->reload_id;
            if ( p->disable_inspect )
                return;
        }

        if ( !p->flow->service )
            ::execute<T>(p, fp->network.vec, fp->network.num);

        if ( p->disable_inspect )
            return;

        if ( p->flow->full_inspection() )
            full_inspection<T>(p);

        if ( !p->disable_inspect and !p->flow->is_inspection_disabled() )
            ::execute<T>(p, tp->control.vec, tp->control.num);
    }

    if ( T )
        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "stop inspection, %s, packet %" PRId64", context %" PRId64", total time: %" PRId64" usec\n",
            packet_type, p->context->packet_number, p->context->context_num, TO_USECS(timer.get()));
}

void InspectorManager::probe(Packet* p)
{
    GlobalInspectorPolicy* pp = p->context->conf->policy_map->get_global_inspector_policy();
    assert(pp);

    if ( !trace_enabled(snort_trace, TRACE_INSPECTOR_MANAGER, DEFAULT_TRACE_LOG_LEVEL, p) )
        ::execute<false>(p, pp->probe.vec, pp->probe.num, true);
    else
    {
        Stopwatch<SnortClock> timer;
        const char* packet_type = p->is_rebuilt() ? "rebuilt" : "raw";
        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "post detection inspection, %s, packet %" PRId64", context %" PRId64"\n",
            packet_type, p->context->packet_number, p->context->context_num);

        timer.start();

        ::execute<true>(p, pp->probe.vec, pp->probe.num, true);

        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "end inspection, %s, packet %" PRId64", context %" PRId64", total time: %" PRId64" usec\n",
            packet_type, p->context->packet_number, p->context->context_num, TO_USECS(timer.get()));
    }
}

void InspectorManager::clear(Packet* p)
{
    if ( !p->context->clear_inspectors )
        return;

    if ( p->flow and p->flow->gadget )
        p->flow->gadget->clear(p);

    p->context->clear_inspectors = false;
}

