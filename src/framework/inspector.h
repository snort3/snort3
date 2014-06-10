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

#include "main/snort_types.h"
#include "main/thread.h"
#include "framework/base_api.h"

struct Packet;
struct SnortConfig;

typedef int16_t ServiceId;

// this is the current version of the api
#define INSAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define INSAPI_PLUGIN_V0 0

struct ServiceTag
{
    const uint8_t* tag;
    unsigned len;
    bool to_server;
};

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

class Inspector
{
public:
    // main thread functions
    virtual ~Inspector();

    // access external dependencies here
    // return verification status
    virtual bool configure(SnortConfig*) { return true; };
    virtual void show(SnortConfig*) { };

    // packet thread functions
    virtual void pinit() { };
    virtual void pterm() { };

    virtual void eval(Packet*) = 0;
    virtual void meta(int, const uint8_t*) { };

    // framework support
    unsigned get_ref(unsigned i) { return ref_count[i]; };
    void set_ref(unsigned i, unsigned r) { ref_count[i] = r; };

    void add_ref() { ++ref_count[slot]; };
    void rem_ref() { --ref_count[slot]; };

    bool is_inactive();

    void set_service(ServiceId id) { srv_id = id; };
    ServiceId get_service() { return srv_id; };

    // IT_SERVICE only
    virtual class StreamSplitter* get_splitter(bool /*to_server*/)
    { return nullptr; };

public:
    static unsigned max_slots;
    static THREAD_LOCAL unsigned slot;

protected:
    // main thread functions
    Inspector();  // internal init only at this point

private:
    unsigned* ref_count;
    ServiceId srv_id;
};

enum InspectorType
{
    IT_PACKET,
    IT_PROTOCOL,
    IT_STREAM,
    IT_SESSION,
    IT_SERVICE,
    IT_MAX
};

typedef Inspector* (*InspectNew)(Module*);
typedef void (*InspectDelFunc)(Inspector*);
typedef void (*InspectFunc)();
typedef class Session* (*InspectSsnFunc)(class Flow*);
typedef struct ContentBuffer* (*InspectBufFunc)(unsigned);

// FIXIT ensure all provide stats
struct InspectApi
{
    BaseApi base;
    InspectorType type;
    uint16_t proto_bits;

    const char* service;   // nullptr when type != IT_SERVICE
    //ServiceTag tags;       // null terminated list of tags

    // list of thread local detection buffers captured by inspector
    const char* contents;  // space separated, eg "foo_a foo_b foo_c" 

    // main thread funcs - parse time data only
    InspectFunc init;      // allocate process static data
    InspectFunc term;      // release init() data
    InspectNew ctor;       // instantiate inspector from Module data
    InspectDelFunc dtor;   // release inspector instance

    // packet thread funcs - runtime data only
    InspectFunc pinit;     // plugin thread local allocation
    InspectFunc pterm;     // plugin thread local cleanup
    InspectSsnFunc ssn;    // purge caches
    InspectFunc sum;       // accumulate stats
    InspectFunc stats;     // output stats
    InspectFunc reset;     // clear stats
    InspectBufFunc getbuf; // 0-based, eg getbuf(1) means foo_b above
};

#endif

