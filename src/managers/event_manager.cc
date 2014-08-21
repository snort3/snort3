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

static OutputSet s_alerters;
static OutputSet s_loggers;
static OutputSet s_unified;

bool EventManager::alert_enabled = true;
bool EventManager::log_enabled = true;

//-------------------------------------------------------------------------
// output plugins
//-------------------------------------------------------------------------

void EventManager::add_plugin(const LogApi* api)
{
    s_outputs.push_back(new Output(api));
}

void EventManager::release_plugins()
{
    s_alerters.outputs.clear();
    s_loggers.outputs.clear();
    s_unified.outputs.clear();

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

static Output* get_out(const char *keyword)
{
    for ( auto* p : s_outputs )
        if ( !strcasecmp(p->api->base.name, keyword) )
            return p;

    return NULL;
}

unsigned EventManager::get_output_type_flags(char *keyword)
{
    Output* p = get_out(keyword);

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
    p->handler = p->api->ctor(sc, mod);
    assert(p->handler);  // FIXIT-H must handle case where not configured

    if ( (p->api->flags & OUTPUT_TYPE_FLAG__ALERT) &&
        (p->api->flags & OUTPUT_TYPE_FLAG__LOG) )
    {
        if ( alert_enabled && log_enabled )
            s_unified.outputs.push_back(p->handler);
    }
    else if ( p->api->flags & OUTPUT_TYPE_FLAG__ALERT )
    {
        if ( alert_enabled )
            s_alerters.outputs.push_back(p->handler);
    }

    else if ( p->api->flags & OUTPUT_TYPE_FLAG__LOG )
    {
        if ( log_enabled )
            s_loggers.outputs.push_back(p->handler);
    }
    else
        FatalError("logger has no type %s\n", p->api->base.name);
}

// command line outputs
void EventManager::instantiate(
    const char* name, SnortConfig* sc)
{
    Module* mod = ModuleManager::get_module(name);
    Output* p = get_out(name);

    if ( !mod || !p )
    {
        FatalError("unknown logger %s\n", name);
        return;
    }

    // FIXIT-H this loses args if set in conf
    // emulate a config like name = { }
    //mod->begin(name, 0, sc);
    //mod->end(name, 0, sc);

    // override prior outputs
    // (last cmdline option wins)
    s_alerters.outputs.clear();
    s_loggers.outputs.clear();
    s_unified.outputs.clear();

    instantiate(p, mod, sc);
}

// conf outputs
void EventManager::instantiate(
    const LogApi* api, Module* mod, SnortConfig* sc)
{
    Output* p = get_out(api->base.name);
    instantiate(p, mod, sc);
}

//-------------------------------------------------------------------------
// execution

void EventManager::open_outputs()
{
    for ( auto p : s_alerters.outputs )
        p->open();

    for ( auto p : s_loggers.outputs )
        p->open();

    for ( auto p : s_unified.outputs )
        p->open();
}

void EventManager::close_outputs()
{
    for ( auto p : s_alerters.outputs )
        p->close();

    for ( auto p : s_loggers.outputs )
        p->close();

    for ( auto p : s_unified.outputs )
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
    for ( auto p : s_alerters.outputs )
        p->alert(pkt, message, event);

    for ( auto p : s_unified.outputs )
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

    for ( auto p : s_unified.outputs )
        p->log(pkt, message, event);
}

