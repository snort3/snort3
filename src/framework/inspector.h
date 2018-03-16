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
// inspector.h author Russ Combs <rucombs@cisco.com>

#ifndef INSPECTOR_H
#define INSPECTOR_H

// Inspectors are the workhorse that do all the heavy lifting between
// decoding a packet and detection.  There are several types that operate
// in different ways.  These correspond to Snort 2X preprocessors.

#include <atomic>

#include "framework/base_api.h"
#include "main/thread.h"
#include "target_based/snort_protocols.h"

class Session;

namespace snort
{
struct SnortConfig;
struct Packet;

// this is the current version of the api
#define INSAPI_VERSION ((BASE_API_VERSION << 16) | 0)

struct InspectionBuffer
{
    enum Type
    {
        // FIXIT-L file data is tbd
        IBT_KEY, IBT_HEADER, IBT_BODY, IBT_FILE, IBT_ALT, IBT_MAX
    };
    const uint8_t* data;
    unsigned len;
};

struct InspectApi;

//-------------------------------------------------------------------------
// api for class
//-------------------------------------------------------------------------

class SO_PUBLIC Inspector
{
public:
    // main thread functions
    virtual ~Inspector();

    Inspector(const Inspector&) = delete;
    Inspector& operator=(const Inspector&) = delete;

    // access external dependencies here
    // return verification status
    virtual bool configure(SnortConfig*) { return true; }
    virtual void show(SnortConfig*) { }
    virtual void update(SnortConfig*, const char*) { }

    // packet thread functions
    // tinit, tterm called on default policy instance only
    virtual void tinit() { }   // allocate configurable thread local
    virtual void tterm() { }   // purge only, deallocate via api

    // screen incoming packets; only liked packets go to eval
    // default filter is per api proto / paf
    virtual bool likes(Packet*);

    // clear is a bookend to eval() for the active service inspector
    // clear is called when Snort is done with the previously eval'd
    // packet to release any thread-local or flow-based data
    virtual void eval(Packet*) = 0;
    virtual void clear(Packet*) { }

    virtual void meta(int, const uint8_t*) { }
    virtual int exec(int, void*) { return 0; }

    // framework support
    unsigned get_ref(unsigned i) { return ref_count[i]; }
    void set_ref(unsigned i, unsigned r) { ref_count[i] = r; }

    void add_ref();
    void rem_ref();

    bool is_inactive();

    void set_service(SnortProtocolId snort_protocol_id_param)
    {
        snort_protocol_id = snort_protocol_id_param;
    }

    SnortProtocolId get_service() { return snort_protocol_id; }

    // for well known buffers
    // well known buffers may be included among generic below,
    // but they must be accessible from here
    virtual bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&)
    { return false; }

    // for generic buffers
    // key is listed in api buffers
    // id-1 is zero based index into buffers array
    unsigned get_buf_id(const char* key);
    virtual bool get_buf(const char* key, Packet*, InspectionBuffer&);
    virtual bool get_buf(unsigned /*id*/, Packet*, InspectionBuffer&)
    { return false; }

    virtual bool get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& bf)
    { return get_buf(ibt, p, bf); }

    // IT_SERVICE only
    virtual class StreamSplitter* get_splitter(bool to_server);

    void set_api(const InspectApi* p)
    { api = p; }

    const InspectApi* get_api()
    { return api; }

    const char* get_name();

public:
    static unsigned max_slots;
    static THREAD_LOCAL unsigned slot;

protected:
    // main thread functions
    Inspector();  // internal init only at this point

private:
    const InspectApi* api;
    std::atomic_uint* ref_count;
    SnortProtocolId snort_protocol_id;
};

template <typename T>
class InspectorData : public Inspector
{
public:
    InspectorData(T* t)
    { data = t; }

    ~InspectorData() override
    { delete data; }

    void eval(Packet*) override { }

    T* data;
};

// at present there is no sequencing among like types except that appid
// is always first among controls.

enum InspectorType
{
    IT_PASSIVE,  // config only, or data consumer (eg file_log, binder, ftp_client)
    IT_BINDER,   // maps config to traffic
    IT_WIZARD,   // guesses service inspector
    IT_PACKET,   // processes raw packets only (eg normalize, capture)
    IT_STREAM,   // flow tracking and reassembly (eg ip, tcp, udp)
    IT_NETWORK,  // process packets w/o service (eg arp, bo, rep)
    IT_SERVICE,  // extract and analyze service PDUs (eg dce, http, ssl)
    IT_CONTROL,  // process all packets before detection (eg appid)
    IT_PROBE,    // process all packets after detection (eg perf_monitor, port_scan)
    IT_MAX
};

typedef Inspector* (* InspectNew)(Module*);
typedef void (* InspectDelFunc)(Inspector*);
typedef void (* InspectFunc)();
typedef Session* (* InspectSsnFunc)(class Flow*);

struct InspectApi
{
    BaseApi base;
    InspectorType type;
    uint16_t proto_bits;

    const char** buffers;  // null terminated list of exported buffers
    const char* service;   // nullptr when type != IT_SERVICE

    InspectFunc pinit;     // plugin init
    InspectFunc pterm;     // cleanup pinit()
    InspectFunc tinit;     // thread local init
    InspectFunc tterm;     // cleanup tinit()
    InspectNew ctor;       // instantiate inspector from Module data
    InspectDelFunc dtor;   // release inspector instance
    InspectSsnFunc ssn;    // get new session tracker
    InspectFunc reset;     // clear stats
};

inline const char* Inspector::get_name()
{ return api->base.name; }
}

#endif

