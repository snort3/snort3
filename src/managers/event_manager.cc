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
// event_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event_manager.h"

#include <cassert>
#include <list>

#include "framework/logger.h"
#include "log/messages.h"
#include "main/snort_config.h"

#include "module_manager.h"

using namespace snort;
using namespace std;

struct Output
{
    const LogApi* api;
    Logger* handler;

    Output(const LogApi* p)
    { api = p; handler = nullptr; }

    ~Output()
    { api->dtor(handler); }
};

typedef list<Output*> OutputList;
static OutputList s_outputs;

typedef list<Logger*> EHList;

struct OutputSet
{
    EHList outputs;
};

static OutputSet s_loggers;

bool EventManager::alert_enabled = true;
bool EventManager::log_enabled = true;

//-------------------------------------------------------------------------
// output plugins
//-------------------------------------------------------------------------

void EventManager::add_plugin(const LogApi* api)
{
    // can't assert - alert_sf_socket operates differently
    //assert(api->flags & (OUTPUT_TYPE_FLAG__ALERT | OUTPUT_TYPE_FLAG__LOG));
    s_outputs.push_back(new Output(api));
}

void EventManager::release_plugins()
{
    s_loggers.outputs.clear();

    for ( auto* p : s_outputs )
        delete p;

    s_outputs.clear();
}

void EventManager::dump_plugins()
{
    Dumper d("Loggers");

    for ( auto* p : s_outputs )
        d.dump(p->api->base.name, p->api->base.version);
}

//-------------------------------------------------------------------------
// lookups

static Output* get_out(const char* key)
{
    for ( auto* p : s_outputs )
        if ( !strcasecmp(p->api->base.name, key) )
            return p;

    return nullptr;
}

static Output* get_out(const char* key, const char* pfx)
{
    Output* p = get_out(key);

    if ( p )
        return p;

    if ( !strncmp(key, pfx, strlen(pfx)) )
        return nullptr;

    string s = pfx;
    s += key;

    p = get_out(s.c_str());

    return p;
}

unsigned EventManager::get_output_type_flags(char* key)
{
    Output* p = get_out(key);

    if ( p )
        return p->api->flags;

    return OUTPUT_TYPE_FLAG__NONE;
}

//-------------------------------------------------------------------------
// list foo

void EventManager::release_outputs(OutputSet* ofn)
{
    delete ofn;
}

void EventManager::add_output(OutputSet** ofn, Logger* eh)
{
    if ( !*ofn )
        *ofn = new OutputSet;

    (*ofn)->outputs.push_back(eh);
}

void EventManager::copy_outputs(OutputSet* dst, OutputSet* src)
{
    dst->outputs = src->outputs;
}

//-------------------------------------------------------------------------
// configuration

void EventManager::instantiate(
    Output* p, Module* mod, SnortConfig* sc)
{
    bool enabled = false;

    if ( (p->api->flags & OUTPUT_TYPE_FLAG__ALERT) && alert_enabled )
        enabled = true;

    if ( (p->api->flags & OUTPUT_TYPE_FLAG__LOG) && log_enabled )
        enabled = true;

    if ( !enabled )
        return;

    p->handler = p->api->ctor(sc, mod);
    assert(p->handler);

    p->handler->set_api(p->api);
    s_loggers.outputs.push_back(p->handler);
}

// command line outputs
void EventManager::instantiate(
    const char* name, SnortConfig* sc)
{
    // override prior outputs
    // (last cmdline option wins)
    s_loggers.outputs.clear();

    const char* pfx = (sc->output_flags & OUTPUT_FLAG__ALERTS) ? "alert_" : "log_";
    Output* p = get_out(name, pfx);

    if ( !p )
    {
        ParseError("unknown logger %s", name);
        return;
    }

    sc->output = name = p->api->base.name;

    if ( p->handler )
    {
        // configured by conf
        s_loggers.outputs.push_back(p->handler);
        return;
    }
    Module* mod = ModuleManager::get_default_module(name, sc);
    instantiate(p, mod, sc);
}

// conf outputs
void EventManager::instantiate(
    const LogApi* api, Module* mod, SnortConfig* sc)
{
    // FIXIT-L instantiate each logger from conf at most once
    Output* p = get_out(api->base.name);

    if ( p && !p->handler )
        instantiate(p, mod, sc);
}

//-------------------------------------------------------------------------
// execution

void EventManager::open_outputs()
{
    for ( auto p : s_loggers.outputs )
        p->open();
}

void EventManager::close_outputs()
{
    for ( auto p : s_loggers.outputs )
        p->close();
}

void EventManager::call_alerters(
    OutputSet* idx, Packet* pkt, const char* message, const Event& event)
{
    if ( idx )
    {
        for ( auto p : idx->outputs )
            p->alert(pkt, message, event);
        return;
    }
    for ( auto p : s_loggers.outputs )
        p->alert(pkt, message, event);
}

void EventManager::call_loggers(
    OutputSet* idx, Packet* pkt, const char* message, Event* event)
{
    if ( idx )
    {
        for ( auto p : idx->outputs )
            p->log(pkt, message, event);
        return;
    }
    for ( auto p : s_loggers.outputs )
        p->log(pkt, message, event);
}

#ifdef PIGLET

//-------------------------------------------------------------------------
// piglet breach
//-------------------------------------------------------------------------
static const LogApi* find_api(const char* name)
{
    for ( auto out : s_outputs )
        if ( !strcmp(out->api->base.name, name) )
            return out->api;

    return nullptr;
}

LoggerWrapper* EventManager::instantiate(const char* name, Module* m, SnortConfig* sc)
{
    auto api = find_api(name);
    if ( !api || !api->ctor )
        return nullptr;

    auto p = api->ctor(sc, m);
    if ( !p )
        return nullptr;

    return new LoggerWrapper(api, p);
}

#endif

