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
#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;
using namespace std;

class Output : public PlugInterface
{
public:
    const LogApi* api;
    Logger* handler;

    Output(const LogApi* p)
    { api = p; handler = nullptr; }

    ~Output() override
    { api->dtor(handler); }

    void instantiate(Module* mod, SnortConfig* sc, const char*) override
    {
        if ( !handler )
            EventManager::instantiate(this, mod, sc);
    }
};

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

PlugInterface* EventManager::get_interface(const LogApi* api)
{
    assert(api->flags & (OUTPUT_TYPE_FLAG__ALERT | OUTPUT_TYPE_FLAG__LOG));
    return new Output(api);
}

void EventManager::release_plugins()
{
    s_loggers.outputs.clear();
}

//-------------------------------------------------------------------------
// lookups

static Output* get_out(const char* key)
{ return (Output*)PluginManager::get_interface(key); }

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

    (*ofn)->outputs.emplace_back(eh);
}

void EventManager::copy_outputs(OutputSet* dst, const OutputSet* src)
{
    if (dst && src && src->outputs.size())
        dst->outputs = src->outputs;
}

//-------------------------------------------------------------------------
// configuration

void EventManager::instantiate(
    Output* p, Module* mod, SnortConfig*)
{
    bool enabled = false;

    if ( (p->api->flags & OUTPUT_TYPE_FLAG__ALERT) && alert_enabled )
        enabled = true;

    if ( (p->api->flags & OUTPUT_TYPE_FLAG__LOG) && log_enabled )
        enabled = true;

    if ( !enabled )
        return;

    p->handler = p->api->ctor(mod);
    assert(p->handler);

    p->handler->set_api(p->api);
    s_loggers.outputs.emplace_back(p->handler);
}

// command line outputs
void EventManager::instantiate(const char* name, SnortConfig* sc)
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
        s_loggers.outputs.emplace_back(p->handler);
        return;
    }
    Module* mod = PluginManager::get_module(name);
    ModuleManager::set_defaults(mod, sc);
    instantiate(p, mod, sc);
    PluginManager::set_instantiated(name);
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

void EventManager::reload_outputs()
{
    for ( auto p : s_loggers.outputs )
        p->reload();
    LogMessage("logger file reinitialized\n");
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

