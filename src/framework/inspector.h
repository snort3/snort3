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
// inspector.h author Russ Combs <rucombs@cisco.com>

#ifndef INSPECTOR_H
#define INSPECTOR_H

#include "snort_types.h"
#include "thread.h"
#include "framework/base_api.h"

struct Packet;
struct SnortConfig;

// this is the current version of the api
#define INSAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define INSAPI_PLUGIN_V0 0

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

class Inspector
{
public:
    virtual ~Inspector();

    virtual void configure(SnortConfig*) { };
    virtual int verify(SnortConfig*) { return 0; };

    virtual void setup(SnortConfig*) { };  // unprivileged init, stream_api etc.
    virtual void show(SnortConfig*) { };

    virtual void eval(Packet*) = 0;
    virtual void meta(int, const uint8_t*) { };

    virtual void init() { };   // allocate thread local runtime data based on config
    virtual void term() { };   // release thread local runtime data
    virtual void reset() { };  // 

    unsigned get_ref(unsigned i) { return ref_count[i]; };
    void set_ref(unsigned i, unsigned r) { ref_count[i] = r; };

    void add_ref() { ++ref_count[slot]; };
    void rem_ref() { --ref_count[slot]; };

    bool is_inactive();

    static unsigned max_slots;
    static THREAD_LOCAL unsigned slot;

protected:
    Inspector();

private:
    unsigned* ref_count;
};

enum Priority {
    PRIORITY_PACKET,
    PRIORITY_NETWORK,
    PRIORITY_TRANSPORT,
    PRIORITY_TUNNEL,
    PRIORITY_SCANNER,
    PRIORITY_SESSION,
    PRIORITY_APPLICATION,
    PRIORITY_MAX
};

typedef void (*PreprocFunc)();
typedef void* (*PreprocInitFunc)(void*);

// FIXIT these should take no arg now
typedef void (*PreprocClassFunc)(void*);

typedef Inspector* (*PreprocCtorFunc)(Module*);
typedef void (*PreprocDtorFunc)(Inspector*);

// FIXIT ensure all pp's provide stats
struct InspectApi
{
    BaseApi base;
    Priority priority;
    uint16_t proto_bits;

    // main thread funcs - parse time data only
    PreprocFunc init;        // allocate process static data
    PreprocFunc term;        // release init() data

    PreprocCtorFunc ctor;
    PreprocDtorFunc dtor;

    // packet thread funcs - runtime data only
    PreprocClassFunc stop;   // stop packet processing  // FIXIT same as purge?
    PreprocClassFunc purge;  // purge caches
    PreprocClassFunc sum;    // accumulate stats
    PreprocClassFunc stats;  // output stats
    PreprocClassFunc reset;  // clear stats
};

#endif

