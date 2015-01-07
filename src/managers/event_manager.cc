//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "event_manager.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <list>
using namespace std;

#include "snort_types.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "plugin_manager.h"
#include "module_manager.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "loggers/loggers.h"
#include "parser/parser.h"
#include "log/messages.h"

struct Output
{
    const LogApi* api;
    Logger* handler;

    Output(const LogApi* p)
    { api = p; handler = nullptr; };

    ~Output()
    { api->dtor(handler); };
};

typedef list<Output*> OutputList;
static OutputList s_outputs;

typedef list<Logger*> EHList;
static EHList s_handlers;

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

    return NULL;
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

    Output* p = get_out(name);

    if ( !p )
    {
        ParseError("unknown logger %s\n", name);
        return;
    }
    else if ( p->handler )
    {
        // configured by conf
        s_loggers.outputs.push_back(p->handler);
        return;
    }
    Module* mod = ModuleManager::get_module(name);

    if ( mod )
    {
        // emulate a config like name = { }
        mod->begin(name, 0, sc);
        mod->end(name, 0, sc);
    }
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
    OutputSet* idx, Packet* pkt, const char *message, Event *event)
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
    OutputSet* idx, Packet* pkt, const char *message, Event *event)
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

