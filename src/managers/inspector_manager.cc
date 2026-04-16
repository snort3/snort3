//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "detection/detection_engine.h"
#include "detection/fp_utils.h"
#include "flow/expect_flow.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "log/log_stats.h"
#include "log/messages.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/snort_module.h"
#include "main/thread_config.h"
#include "packet_io/packet_tracer.h"
#include "protocols/packet.h"
#include "profiler/profiler_defs.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "search_engines/search_tool.h"
#include "stream/base/stream_module.h"
#include "target_based/snort_protocols.h"
#include "time/clock_defs.h"
#include "time/stopwatch.h"
#include "trace/trace_api.h"

#include "module_manager.h"
#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;
using namespace std;

#define app_id "appid"
#define bind_id "binder"
#define file_id "file_inspect"
#define wiz_id "wizard"

static void instantiate(const InspectApi*, Module*, SnortConfig*, const char*);

//-------------------------------------------------------------------------
// interface with plugin manager
//-------------------------------------------------------------------------

class InspectorContext : public PlugContext
{
public:
    InspectorContext(const InspectApi* api) : api(api) { }

public:
    const InspectApi* api = nullptr;
    bool in_play = false;
    bool once = false;
};

class PlugInspect : public PlugInterface
{
public:
    PlugInspect(const InspectApi* api) : api(api) { }

    void global_init() override
    {
        if ( api->pinit )
            api->pinit();
    }

    void global_term() override
    {
        if ( api->pterm )
            api->pterm();
    }

    void thread_init() override
    {
        if ( api->tinit )
            api->tinit();
    }

    void thread_term() override
    {
        if ( api->tterm )
            api->tterm();
    }

    void instantiate(Module* mod, SnortConfig* sc, const char* name) override
    {
        ::instantiate(api, mod, sc, name);
    }

    PlugContext* get_context() override
    { return new InspectorContext(api); }

public:
    const InspectApi* api;
};

//-------------------------------------------------------------------------
// indirection stuff
//-------------------------------------------------------------------------

using InspectorIndex = unsigned;

struct InspectorData
{
    InspectorData(NetworkPolicy* n, InspectionPolicy* i, const char* s, Inspector* h = nullptr) :
        np(n), ip(i), name(s), pin(h) { }

    NetworkPolicy* np;
    InspectionPolicy* ip;

    std::string name;
    Inspector* pin;

    bool needs_tinit = true;
    bool needs_tterm = false;
    bool was_configured = false;
};

struct InspectorKey
{
    string name;
    uint64_t np_id = 0;
    uint64_t ip_id = 0;

    InspectorKey(const InspectorData&);
    InspectorKey(const char*, Module::Usage);
    InspectorKey(const char*, uint64_t, uint64_t);
};

InspectorKey::InspectorKey(const InspectorData& insd) :
    name(insd.name)
{
    np_id = insd.np ? insd.np->user_policy_id : 0;
    ip_id = insd.ip ? insd.ip->user_policy_id : 0;
}

InspectorKey::InspectorKey(const char* s, Module::Usage use)
{
    switch ( use )
    {
    case Module::CONTEXT:
        np_id = get_network_policy()->user_policy_id;
        break;

    case Module::INSPECT:
        np_id = get_network_policy()->user_policy_id;
        ip_id = get_inspection_policy()->user_policy_id;
        break;

    default:
        break;
    }
    name = s;
}

InspectorKey::InspectorKey(const char* s, uint64_t npid, uint64_t ipid) :
    name(s)
{
    np_id = npid;
    ip_id = ipid;
}

struct IdComp
{
    bool operator()(const InspectorKey& a, const InspectorKey& b) const
    {
        if ( a.np_id != b.np_id )
            return a.np_id < b.np_id;

        if ( a.ip_id != b.ip_id )
            return a.ip_id < b.ip_id;

        return a.name < b.name;
    }
};

struct InspectorVector
{
    std::vector<InspectorData> iv;
    std::map<InspectorKey, InspectorIndex, IdComp> im;

    InspectorIndex add(NetworkPolicy* np, InspectionPolicy* ip, const char* s, Inspector* h)
    {
        iv.emplace_back(np, ip, s, h);
        return iv.size() - 1;
    }

    void fill_map()
    {
        for ( auto& insd : iv )
        {
            InspectorIndex iid = &insd - &iv[0];
            InspectorKey ink(insd);
            im[ink] = iid;
        }
    }

    void thread_init(bool all = false)
    {
        for ( auto& insd : iv )
        {
            if ( insd.pin and (insd.needs_tinit or all) )
                insd.pin->tinit();
        }
    }

    void thread_term(bool all = false)
    {
        for ( auto& insd : iv )
        {
            if ( insd.pin and (insd.needs_tterm or all) )
            {
                set_network_policy(insd.np);
                insd.pin->tterm();
            }
        }

        set_network_policy(SnortConfig::get_conf()->policy_map->get_network_policy(0));
    }

    void tear_down(SnortConfig* sc)
    {
        for ( auto& insd : iv )
        {
            if ( insd.pin and insd.was_configured )
                insd.pin->tear_down(sc, true);
        }
    }

    void clear_init()
    {
        for ( auto& insd : iv )
        { insd.needs_tinit = false; }
    }

    Inspector* get_pin(InspectorIndex iid) const
    {
        assert(iid < iv.size());
        assert(iv[iid].pin);
        return iv[iid].pin;
    }

    Inspector* get_inspector(const InspectorKey& ink) const
    {
        auto it = im.find(ink);
        return (it == im.end()) ? nullptr : get_pin(it->second);
    }
};

static THREAD_LOCAL InspectorVector* curr_iv = nullptr;
static InspectorVector* prev_iv = nullptr;

void InspectorManager::new_map()
{
    if ( curr_iv )
    {
        assert(!prev_iv);
        prev_iv = curr_iv;
    }
    curr_iv = new InspectorVector;
}

void InspectorManager::prepare_map()
{
    curr_iv->fill_map();
}

void InspectorManager::tear_down(SnortConfig* sc)
{
    curr_iv->tear_down(sc);
}

void InspectorManager::abort_map()
{
    delete curr_iv;
    curr_iv = prev_iv;
    prev_iv = nullptr;
}

void InspectorManager::cleanup()
{
    delete curr_iv;
    curr_iv = nullptr;

    delete prev_iv;
    prev_iv = nullptr;
}

InspectorVector* InspectorManager::get_map()
{
    return curr_iv;
}

void InspectorManager::set_map(InspectorVector* iv)
{
    curr_iv = iv;
}

void InspectorManager::revert_map()
{
    InspectorVector* tmp = curr_iv;
    curr_iv = prev_iv;
    prev_iv = tmp;
}

void InspectorManager::restore_map()
{
    // for clarity, swap back first
    revert_map();

    curr_iv->clear_init();

    delete prev_iv;
    prev_iv = nullptr;
}

void InspectorManager::update_map()
{
    curr_iv->clear_init();
}

void InspectorManager::reconcile_map(SnortConfig* sc)
{
    assert(curr_iv);
    assert(prev_iv);

    for ( const auto& nit : curr_iv->im )
    {
        const auto oit = prev_iv->im.find(nit.first);

        if ( oit != prev_iv->im.end() )
        {
            Inspector* new_guy = curr_iv->iv[nit.second].pin;
            Inspector* old_guy = prev_iv->iv[oit->second].pin;

            new_guy->copy_thread_storage(old_guy);
            new_guy->install_reload_handler(sc);

            assert(!prev_iv->iv[oit->second].needs_tinit);
            curr_iv->iv[nit.second].needs_tinit = false;
        }
    }

    for ( const auto& oit : prev_iv->im )
    {
        const auto nit = curr_iv->im.find(oit.first);

        if ( nit == curr_iv->im.end() )
        {
            InspectorData& insd = prev_iv->iv[oit.second];

            if ( !insd.needs_tinit )
            {
                insd.needs_tterm = true;
                insd.pin->tear_down(sc, false);
            }
        }
    }
}

//-------------------------------------------------------------------------
// instance stuff
//-------------------------------------------------------------------------

struct PHInstance
{
public:
    InspectorIndex iid = 0;

    PHInstance(SnortConfig*, Module*, const char*, NetworkPolicy*, InspectionPolicy*);

    ~PHInstance();

    Inspector* get_handler() const
    {
        Inspector* pi = curr_iv->get_pin(iid);
        return pi;
    }

    static bool comp(const PHInstance* a, const PHInstance* b)
    { return ( a->get_type() < b->get_type() ); }

    const InspectApi* get_api() const
    { return get_handler()->get_api(); }

    InspectorType get_type() const
    { return get_api()->type; }

    const char* get_key() const
    { return get_handler()->get_alias_name(); }

    bool is(const char* s) const
    { return !strcmp(get_key(), s); }

    bool disable(SnortConfig* sc) const
    { return get_handler()->disable(sc); }
};

PHInstance::PHInstance(SnortConfig* sc, Module* mod, const char* alias, NetworkPolicy* np, InspectionPolicy* ip)
{
    InspectorContext* icon = (InspectorContext*)PluginManager::get_context(mod->get_name());
    assert(icon);

    icon->once = (mod->get_usage() == Module::INSPECT);
    Inspector* pi = icon->api->ctor(mod);

    if ( !pi )
        return;

    pi->set_api(icon->api);
    pi->add_global_ref();

    if ( icon->api->service )
        pi->set_service(sc->proto_ref->add(icon->api->service));

    const char* s = alias ? alias : pi->get_name();
    pi->set_alias_name(s);
    iid = curr_iv->add(np, ip, s, pi);
}

PHInstance::~PHInstance()
{
}

typedef vector<PHInstance*> PHInstanceList;

struct PHVector
{
    std::vector<PHInstance*> vec;

    PHVector() = default;

    void add(PHInstance* p)
    {
        vec.push_back(p);
    }

    void add_control(PHInstance*);
};

// a more sophisticated approach to handling controls etc. may be
// warranted such as a configuration or priority scheme (a la 2X).
// for now we only require that appid run first among controls.

void PHVector::add_control(PHInstance* p)
{
    if ( !p->is(app_id) or vec.empty() )
        add(p);
    else
    {
        add(vec[0]);
        vec[0] = p;
    }
}

//-------------------------------------------------------------------------
// trash stuff
//-------------------------------------------------------------------------

struct Trash
{
    std::shared_ptr<Plugin> plugin = nullptr;
    Inspector* pin;

    Trash(Inspector* p) :
        plugin(PluginManager::get_plugin(p->get_name()))
    { pin = p; }
};

using TrashCan = list<Trash*>;

static TrashCan s_trash;
static TrashCan s_trash2;

static void purge_trash(TrashCan& trash)
{
    while ( !trash.empty() )
    {
        auto* t = trash.front();
        trash.pop_front();

        if ( !t->pin->is_inactive() )
        {
            WarningMessage("Inspector found in the trash is still in use: '%s'.\n", t->pin->get_api()->base.name);

            // if we don't do this we leak at shutdown - the above warning is sufficient
            // (ie we don't have a leak problem but a usage / ref counting problem)
            for (unsigned i = 0; i < 1+ThreadConfig::get_instance_max(); ++i )
                t->pin->set_ref(i, 0);
        }
        t->pin->get_api()->dtor(t->pin);
        delete t;
    }
}

static void empty_trash(TrashCan& trash)
{
    while ( !trash.empty() )
    {
        auto* t = trash.front();
        trash.pop_front();

        if ( !t->pin->is_inactive() )
        {
            trash.emplace_back(t);
            return;
        }

        t->pin->get_api()->dtor(t->pin);
        delete t;
    }
}

//-------------------------------------------------------------------------
// inspector groups
//-------------------------------------------------------------------------

struct PolicyInspectorGroup
{
    virtual ~PolicyInspectorGroup()
    {
        old_np_id = np_id;
        old_ip_id = ip_id;

        for ( auto p : ilist )
        {
            dump_handler(p);
            delete p;
        }
    }

    void dump_handler(const PHInstance* p)
    {
        Inspector* pin = p->get_handler();

        if ( !pin )
            return;

        pin->rem_global_ref();

        if ( pin->is_inactive() )
        {
            pin->get_api()->dtor(pin);
            return;
        }

        Trash* t = new Trash(pin);

        if ( IT_PASSIVE == p->get_type() )
            s_trash2.emplace_back(t);

        else
            s_trash.emplace_back(t);
    }

    PHInstanceList ilist;

    uint64_t np_id = 0;
    uint64_t ip_id = 0;

    static uint64_t old_np_id;
    static uint64_t old_ip_id;

    // subclasses that copy the ilist pointers into vectors
    // must not delete them; that is done above
    virtual void vectorize(SnortConfig*) = 0;

};

uint64_t PolicyInspectorGroup::old_np_id = 0;
uint64_t PolicyInspectorGroup::old_ip_id = 0;

struct TrafficPig : public PolicyInspectorGroup
{
    PHVector packet;
    PHVector control;

    void vectorize(SnortConfig*) override;
};

void TrafficPig::vectorize(SnortConfig* sc)
{
    for ( auto* p : ilist )
    {
        if ( p->disable(sc) )
            continue;

        switch ( p->get_type() )
        {
        case IT_PASSIVE:
            break;

        case IT_PACKET:
            packet.add(p);
            break;

        case IT_CONTROL:
            control.add(p);
            break;

        default:
            ParseError(
                "Network policy (context usage) does not handle inspector %s with type %s\n",
                p->get_key(), InspectApi::get_type(p->get_type()));
            break;
        }
    }
    np_id = get_network_policy()->user_policy_id;
}

struct GlobalPig : public PolicyInspectorGroup
{
    PHVector probe;
    PHVector probe_first;
    PHVector control;

    PHVector flow;
    PHVector file;

    void vectorize(SnortConfig*) override;
};

void GlobalPig::vectorize(SnortConfig* sc)
{
    for ( auto* p : ilist )
    {
        if ( p->disable(sc) )
            continue;

        switch ( p->get_type() )
        {
        case IT_PASSIVE:
            if ( p->is(file_id) )
                file.add(p);
            break;

        case IT_PROBE:
            probe.add(p);
            break;

        case IT_PROBE_FIRST:
            probe_first.add(p);
            break;

        case IT_CONTROL:
            control.add_control(p);
            break;

        case IT_STREAM:
            flow.add(p);
            break;

        default:
            ParseError(
                "Global inspector policy (global usage) does not handle inspector %s with type %s\n",
                p->get_key(), InspectApi::get_type(p->get_type()));
            break;
        }
    }
}

static PHVector& get_flow_tracking(const SnortConfig* sc)
{
    GlobalPig* gp = sc->policy_map->get_global_group();
    return gp->flow;
}

struct ServicePig : public PolicyInspectorGroup
{
    PHVector packet;
    PHVector network;
    PHVector service;

    Inspector* binder = nullptr;
    Inspector* wizard = nullptr;

    std::unordered_map<SnortProtocolId, Inspector*> inspector_cache_by_id;
    std::unordered_map<std::string, Inspector*> inspector_cache_by_service;

    void vectorize(SnortConfig*) override;
    void add_inspector_to_cache(const PHInstance*, SnortConfig*);
};

void ServicePig::add_inspector_to_cache(const PHInstance* p, SnortConfig* sc)
{
    const char* svc = p->get_api()->service;

    if (p->get_type() == IT_SERVICE and svc and p->get_handler())
    {
        SnortProtocolId id = sc->proto_ref->find(svc);
        if (id != UNKNOWN_PROTOCOL_ID)
            inspector_cache_by_id[id] = p->get_handler();
        inspector_cache_by_service[svc] = p->get_handler();
    }
}

static void instantiate_default_binder(SnortConfig*, ServicePig*);

void ServicePig::vectorize(SnortConfig* sc)
{
    for ( auto* p : ilist )
    {
        if ( p->disable(sc) )
            continue;

        switch ( p->get_type() )
        {
        case IT_PASSIVE:
            if ( p->is(bind_id) )
                binder = p->get_handler();
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
            if ( p->is(wiz_id) )
                wizard = p->get_handler();
            else
                service.add(p);
            break;

        default:
            ParseError("Inspection policy does not handle inspector %s with type %s\n",
                p->get_key(), InspectApi::get_type(p->get_type()));
            break;
        }
    }
    np_id = get_network_policy()->user_policy_id;
    ip_id = get_inspection_policy()->user_policy_id;

    // create cache
    inspector_cache_by_id.clear();
    inspector_cache_by_service.clear();

    for ( auto* p : ilist )
        add_inspector_to_cache(p, sc);

    if ( !binder and (!get_flow_tracking(sc).vec.empty() or wizard) )
        instantiate_default_binder(sc, this);
}

//-------------------------------------------------------------------------
// global stuff
//-------------------------------------------------------------------------

std::vector<const InspectApi*> InspectorManager::get_apis()
{
    using Ivec = std::vector<const InspectApi*>;
    Ivec v;

    auto get = [](const BaseApi* pb, void* pv)
    {
        const InspectApi* api = (const InspectApi*)pb;
        ((Ivec*)pv)->push_back(api);
    };
    PluginManager::for_each(PT_INSPECTOR, get, &v);

    return v;
}

const char* InspectorManager::get_inspector_type(const char* name)
{
    const InspectApi* api = (const InspectApi*)PluginManager::get_api(name);
    return api ? api->get_type(api->type) : "";
}

PlugInterface* InspectorManager::get_interface(const InspectApi* api)
{
    return new PlugInspect(api);
}

void InspectorManager::load_buffer_map()
{
    clear_buffer_map();

    auto load = [](const BaseApi* pb, void*)
    {
        const InspectApi* api = (const InspectApi*)pb;
        update_buffer_map(api->buffers, api->service);
    };
    PluginManager::for_each(PT_INSPECTOR, load);
}

void InspectorManager::dump_buffers()
{
    Dumper d("Inspection Buffers");

    auto dump = [](const BaseApi* pb, void* pv)
    {
        const InspectApi* api = (const InspectApi*)pb;
        const char** b = api->buffers;

        while ( b && *b )
        {
            ((Dumper*)pv)->dump(api->base.name, *b);
            ++b;
        }
    };
    PluginManager::for_each(PT_INSPECTOR, dump, &d);
}

void InspectorManager::release_plugins()
{
    purge_trash(s_trash);
    purge_trash(s_trash2);
}

void InspectorManager::empty_trash()
{
    ::empty_trash(s_trash);
    ::empty_trash(s_trash2);
}

//-------------------------------------------------------------------------
// policy stuff
//-------------------------------------------------------------------------

static bool get_instance(PolicyInspectorGroup* pig, const char* keyword, std::vector<PHInstance*>::iterator& it)
{
    for ( it = pig->ilist.begin(); it != pig->ilist.end(); ++it )
    {
        if ( (*it)->is(keyword) )
            return true;
    }
    return false;
}

static PHInstance* get_instance(PolicyInspectorGroup* pig, const char* keyword)
{
    std::vector<PHInstance*>::iterator it;
    return get_instance(pig, keyword, it) ? *it : nullptr;
}

GlobalPig* InspectorManager::create_global_group()
{ return new GlobalPig; }

void InspectorManager::delete_group(GlobalPig* gp)
{ delete gp; }

ServicePig* InspectorManager::create_service_group()
{ return new ServicePig; }

void InspectorManager::delete_group(ServicePig* pig)
{ delete pig; }

TrafficPig* InspectorManager::create_traffic_group()
{ return new TrafficPig; }

void InspectorManager::delete_group(TrafficPig* pig)
{ delete pig; }

Inspector* InspectorManager::get_service_inspector(const char* s)
{
    InspectionPolicy* pi = get_inspection_policy();
    assert(pi and pi->service_group);
    auto g = pi->service_group->inspector_cache_by_service.find(s);
    return (g != pi->service_group->inspector_cache_by_service.end()) ? g->second : nullptr;
}

Inspector* InspectorManager::get_service_inspector(const SnortProtocolId protocol_id)
{
    InspectionPolicy* pi = get_inspection_policy();
    assert(pi and pi->service_group);
    auto g = pi->service_group->inspector_cache_by_id.find(protocol_id);
    return (g != pi->service_group->inspector_cache_by_id.end()) ? g->second : nullptr;
}

InspectSsnFunc InspectorManager::get_session(const char* name, uint16_t proto)
{
    InspectorContext* icon = (InspectorContext*)PluginManager::get_context(name);

    if ( icon->in_play and icon->api->type == IT_STREAM and icon->api->proto_bits == proto )
        return icon->api->ssn;

    assert(!icon->in_play);
    return nullptr;
}

//-------------------------------------------------------------------------
// thread stuff
//-------------------------------------------------------------------------

void InspectorManager::thread_init()
{
    curr_iv->thread_init(true);
}

void InspectorManager::thread_term()
{
    curr_iv->thread_term(true);
}

void InspectorManager::thread_term_removed()
{
    assert(prev_iv);
    prev_iv->thread_term();
}

void InspectorManager::thread_reinit(const SnortConfig*)
{
    curr_iv->thread_init();
}

//-------------------------------------------------------------------------
// config stuff
//-------------------------------------------------------------------------

static bool already_instantiated(PolicyInspectorGroup* pig, const char* s)
{
    return std::any_of(pig->ilist.begin(), pig->ilist.end(),
        [s](const PHInstance* pi) { return pi->is(s); });
}

static void instantiate(const InspectApi* api, Module* mod, SnortConfig* sc, const char* name)
{
    assert(mod);
    const char* keyword = api->base.name;
    InspectorContext* icon = (InspectorContext*)PluginManager::get_context(keyword);

    if ( !icon )
    {
        ParseError("unknown inspector: '%s'.", keyword);
        return;
    }

    if ( name )
        keyword = name;

    icon->in_play = true;

    NetworkPolicy* np = nullptr;
    InspectionPolicy* ip = nullptr;
    PolicyInspectorGroup* pig = nullptr;

    if ( Module::GLOBAL == mod->get_usage() )
    {
        assert(IT_SERVICE != api->type);
        pig = sc->policy_map->get_global_group();

        if ( already_instantiated(pig, mod->get_name()) )
        {
            ParseError("Only one %s inspector may be instantiated\n", mod->get_name());
            return;
        }
    }
    else
    {
        np = get_network_parse_policy();
        if ( !np ) np = get_network_policy();
        assert(np);

        if (Module::CONTEXT == mod->get_usage())
            pig = np->traffic_group;

        else
        {
            ip = get_inspection_policy();
            assert(ip);
            pig = ip->service_group;
        }
    }
    assert(pig);
    PHInstance* ppi = new PHInstance(sc, mod, keyword, np, ip);

    if ( !ppi->get_handler() )
    {
        ParseError("can't instantiate inspector: '%s'.", keyword);
        delete ppi;
        return;
    }

    pig->ilist.emplace_back(ppi);
}

// create default binding for wizard and configured services
static void instantiate_default_binder(SnortConfig* sc, ServicePig* fp)
{
    BinderModule* m = (BinderModule*)PluginManager::get_module(bind_id);

    if ( !m )
        return;

    bool tcp = false, udp = false, pdu = false;

    for ( const auto& p : fp->service.vec )
    {
        const InspectApi& api = *p->get_api();

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

    const InspectApi* api = (const InspectApi*)PluginManager::get_api(bind_id);
    ::instantiate(api, m, sc, bind_id);

    PHInstance* instance = get_instance(fp, bind_id);
    assert(instance);

    fp->binder = instance->get_handler();
    fp->binder->configure(sc);
}

static void vectorize(SnortConfig* sc)
{
    GlobalPig* pp = sc->policy_map->get_global_group();
    pp->vectorize(sc);

    for ( unsigned nidx = 0; nidx < sc->policy_map->network_policy_count(); ++nidx )
    {
        NetworkPolicy* np = sc->policy_map->get_network_policy(nidx);
        assert(np);
        set_network_policy(np);
        np->traffic_group->vectorize(sc);

        for ( unsigned idx = 0; idx < np->inspection_policy_count(); ++idx )
        {
            InspectionPolicy* p = np->get_inspection_policy(idx);
            assert(p);
            set_inspection_policy(p);
            p->configure();
            p->service_group->vectorize(sc);
        }
    }
}

bool InspectorManager::configure(SnortConfig* sc)
{
    bool ok = true;

    for ( auto& insd : curr_iv->iv )
    {
        if ( !insd.pin )
            continue;

        if ( insd.np )
            set_network_policy(insd.np);

        if ( insd.ip )
            set_inspection_policy(insd.ip);

        ok = insd.pin->configure(sc) and ok;
        insd.was_configured = true;
    }

    vectorize(sc);
    return ok;
}

void InspectorManager::prepare_inspectors(SnortConfig*)
{
    for ( auto& insd : curr_iv->iv )
    {
        if ( insd.pin )
            insd.pin->allocate_thread_storage();
    }
}

static std::string generate_inspector_label(const PHInstance* p)
{
    std::string lbl(p->get_api()->base.name);
    const char* name = p->get_key();

    if ( lbl == name )
        lbl += ":";
    else
    {
        lbl += " (";
        lbl += name;
        lbl += "):";
    }
    return lbl;
}

#ifdef SHELL
void InspectorManager::dump_inspector_map()
{
    LogLabel("Inspector to Policy User ID Map");
    LogMessage("(name: network, inspection)\n");

    for ( const auto& it : curr_iv->im )
    {
        auto& insd = curr_iv->iv[it.second];
        uint64_t npid = insd.np ? insd.np->user_policy_id : 0;
        uint64_t ipid = insd.ip ? insd.ip->user_policy_id : 0;
        LogMessage("%*s%s: " STDu64 ", " STDu64 "\n", 8, " ", insd.name.c_str(), npid, ipid);
    }
}
#endif

static void print_config(const PolicyInspectorGroup* pig, const SnortConfig* sc)
{
    std::map<const std::string, const PHInstance*> sorted_ilist;

    for ( const auto* p : pig->ilist )
    {
        std::string name = generate_inspector_label(p);
        sorted_ilist.emplace(name, p);
    }

    for ( const auto& p : sorted_ilist )
    {
        LogLabel(p.first.c_str());
        p.second->get_handler()->show(sc);
    }
}

void InspectorManager::print_config(SnortConfig* sc)
{
    PolicyInspectorGroup* pig = sc->policy_map->get_global_group();

    if (!pig->ilist.empty())
    {
        LogLabel("Global Inspectors");
        ::print_config(pig, sc);
    }

    const auto shell_number = sc->policy_map->shells_count();

    for ( unsigned shell_id = 0; shell_id < shell_number; shell_id++ )
    {
        const auto shell = sc->policy_map->get_shell(shell_id);
        const auto policies = sc->policy_map->get_policies(shell);
        const auto network = policies->network;

        if ( network and network->traffic_group )
        {
            const std::string label = "Network Policy : policy id " +
                std::to_string(network->user_policy_id) + " : " + shell->get_file();
            LogLabel(label.c_str());
            ::print_config(network->traffic_group, sc);
        }

        const auto inspection = policies->inspection;
        if ( inspection )
        {
            assert(inspection->service_group);
            const std::string label = "Inspection Policy : policy id " +
                std::to_string(inspection->user_policy_id) + " : " + shell->get_file();
            LogLabel(label.c_str());
            ::print_config(inspection->service_group, sc);
        }
    }
}

//-------------------------------------------------------------------------
// packet handling
//-------------------------------------------------------------------------

template<bool T>
static inline void execute(
    Packet* p, const PHVector& phv, bool probe = false)
{
    Stopwatch<SnortClock> timer;

    for ( const auto& prep : phv.vec )
    {
        if ( p->packet_flags & PKT_PASS_RULE )
            break;

        // FIXIT-P these checks can eventually be optimized
        // but they are required to ensure that session and app
        // handlers aren't called w/o a session pointer
        if ( !p->flow && (prep->get_type() == IT_SERVICE) )
            break;

        const char* inspector_name = nullptr;
        if ( T )
        {
            timer.reset();
            inspector_name = prep->get_key();
            trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p, "enter %s\n", inspector_name);
            timer.start();
        }

        // FIXIT-L ideally we could eliminate PktType and just use
        // proto_bits but things like teredo need to be fixed up.
        if ( p->type() == PktType::NONE )
        {
            if ( p->proto_bits & prep->get_api()->proto_bits )
                prep->get_handler()->eval(p);
        }
        else if ( BIT((unsigned)p->type()) & prep->get_api()->proto_bits )
            prep->get_handler()->eval(p);

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

    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_SERVICE_CHANGE, p);

    flow->clear_clouseau();

    if ( !flow->gadget )
    {
        if ( !flow->flags.svc_event_generated )
        {
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_NO_SERVICE, p);
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
void inline InspectorManager::full_inspection(Packet* p)
{
    Flow* flow = p->flow;

    if ( flow->service and flow->searching_for_service()
         and (!(p->is_cooked()) or p->is_defrag()) )
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

template<bool T>
inline void InspectorManager::internal_execute(Packet* p)
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
        PHVector& ft = get_flow_tracking(sc);
        if ( !ft.vec.empty() )
            ::execute<T>(p, ft);
        else
        {
            if ( !p->flow )
            {
                stream_base_stats.no_flow_no_inspector++;
                if ( PacketTracer::is_active() )
                    PacketTracer::log("Flow: packet without flow - no flow tracking inspector configured\n");
            }
        }
    }

    // must check between each ::execute()
    if ( p->disable_inspect )
        return;

    unsigned reload_id = SnortConfig::get_reload_id();

    if ( p->flow )
    {
        if ( p->flow->reload_id && p->flow->reload_id != reload_id )
            DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_STATE_RELOADED, p, p->flow);
    }
    else
    {
        if ( p->has_paf_payload() )
        {
            stream_base_stats.no_flow_paf_no_flow++;
            if ( PacketTracer::is_active() )
                PacketTracer::log("Flow: packet without flow - PAF payload but flow was deleted/expired\n");
        }

        DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::PKT_WITHOUT_FLOW, p);
    }

    ServicePig* fp = get_inspection_policy()->service_group;
    assert(fp);

    if ( !p->is_cooked() )
        ::execute<T>(p, fp->packet);

    if ( p->disable_inspect )
        return;

    TrafficPig* tp = get_network_policy()->traffic_group;
    assert(tp);

    if ( !p->is_cooked() )
        ::execute<T>(p, tp->packet);

    if ( p->disable_inspect )
        return;

    GlobalPig* pp = sc->policy_map->get_global_group();
    assert(pp);

    if ( !p->flow )
    {
        ::execute<T>(p, fp->network);

        if ( p->disable_inspect )
            return;

        ::execute<T>(p, pp->control);
        ::execute<T>(p, tp->control);
    }
    else
    {
        if ( !p->has_paf_payload() and p->flow->flow_state == Flow::FlowState::INSPECT )
        {
            Flow& flow = *p->flow;
            flow.session->process(p);
        }

        // cppcheck-suppress duplicateConditionalAssign
        if ( p->flow->reload_id != reload_id )
        {
            p->flow->reload_id = reload_id;
        }

        if ( !p->flow->service )
            ::execute<T>(p, fp->network);

        if ( p->disable_inspect )
            return;

        if ( p->flow->full_inspection() )
            full_inspection<T>(p);

        if ( !p->disable_inspect and !p->flow->is_inspection_disabled() )
            ::execute<T>(p, pp->control);

        if ( !p->disable_inspect and !p->flow->is_inspection_disabled() )
            ::execute<T>(p, tp->control);
    }

    if ( T )
        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "stop inspection, %s, packet %" PRId64", context %" PRId64", total time: %" PRId64" usec\n",
            packet_type, p->context->packet_number, p->context->context_num, TO_USECS(timer.get()));
}

void InspectorManager::execute(Packet* p)
{
    if ( trace_enabled(snort_trace, TRACE_INSPECTOR_MANAGER, DEFAULT_TRACE_LOG_LEVEL, p) )
        internal_execute<true>(p);
    else
        internal_execute<false>(p);

    if ( p->flow )
        p->flow->add_inspection_duration(TO_USECS_FROM_EPOCH(SnortClock::now()) - p->inspection_started_timestamp);

    if ( p->flow && ( !p->is_cooked() or p->is_defrag() ) )
        ExpectFlow::handle_expected_flows(p);
}

void InspectorManager::probe(Packet* p)
{
    GlobalPig* pp = p->context->conf->policy_map->get_global_group();
    assert(pp);

    if ( !trace_enabled(snort_trace, TRACE_INSPECTOR_MANAGER, DEFAULT_TRACE_LOG_LEVEL, p) )
        ::execute<false>(p, pp->probe, true);
    else
    {
        Stopwatch<SnortClock> timer;
        const char* packet_type = p->is_rebuilt() ? "rebuilt" : "raw";
        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "post detection inspection, %s, packet %" PRId64", context %" PRId64"\n",
            packet_type, p->context->packet_number, p->context->context_num);

        timer.start();

        ::execute<true>(p, pp->probe, true);

        trace_ulogf(snort_trace, TRACE_INSPECTOR_MANAGER, p,
            "end inspection, %s, packet %" PRId64", context %" PRId64", total time: %" PRId64" usec\n",
            packet_type, p->context->packet_number, p->context->context_num, TO_USECS(timer.get()));
    }
}

void InspectorManager::probe_first(Packet* p)
{
    GlobalPig* pp = p->context->conf->policy_map->get_global_group();
    assert(pp);
    if ( !trace_enabled(snort_trace, TRACE_INSPECTOR_MANAGER, DEFAULT_TRACE_LOG_LEVEL, p) )
        ::execute<false>(p, pp->probe_first, true);
    else
        ::execute<true>(p, pp->probe_first, true);
}

void InspectorManager::clear(Packet* p)
{
    if ( !p->context->clear_inspectors )
        return;

    if ( p->flow and p->flow->gadget )
        p->flow->gadget->clear(p);

    p->context->clear_inspectors = false;
}

Inspector* InspectorManager::get_binder()
{
    InspectionPolicy* pi = get_inspection_policy();
    assert(pi and pi->service_group);
    return pi->service_group->binder;
}

Inspector* InspectorManager::get_file_inspector(const SnortConfig*)
{
    return get_inspector(file_id, Module::GLOBAL);
}

Inspector* InspectorManager::acquire_file_inspector()
{
    // this check required for FileCacheShare events from non-packet threads
    if ( !curr_iv )
        return nullptr;

    Inspector* pi = get_file_inspector();

    if ( pi )
        pi->add_global_ref();

    return pi;
}

Inspector* InspectorManager::get_inspector(const char* s, Module::Usage use)
{
    InspectorKey ink(s, use);
    return curr_iv->get_inspector(ink);
}

// only valid during swap when curr_iv is outgoing and prev_iv is incoming
Inspector* InspectorManager::get_new_inspector(const char* s)
{
    InspectorKey ink(s, PolicyInspectorGroup::old_np_id, PolicyInspectorGroup::old_ip_id);
    return prev_iv ? prev_iv->get_inspector(ink) : nullptr;
}

// only valid during configure when curr_iv is incoming and prev_iv is outgoing
Inspector* InspectorManager::get_old_inspector(const char* s, Module::Usage use)
{
    InspectorKey ink(s, use);
    return prev_iv ? prev_iv->get_inspector(ink) : nullptr;
}

void InspectorManager::release(Inspector* pi)
{
    assert(pi);
    pi->rem_global_ref();
}

