//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// tracer.h author Pranav Jain <ppramodj@cisco.com>

#ifndef TRACER_H
#define TRACER_H

#include <string>
#include "framework/base_api.h"
#include "main/snort_types.h"
#include "main/thread.h"

namespace snort
{
struct Packet;

#define TRACE_LOGAPI_VERSION ((BASE_API_VERSION << 16) | 1)

#define TRACE_OUTPUT_TYPE_FLAG__NONE   0x0
#define TRACE_OUTPUT_TYPE_FLAG__TRACE  0x1

//-------------------------------------------------------------------------
// API for PT_TRACE Logger
//-------------------------------------------------------------------------

struct TraceLogApi;

class SO_PUBLIC TraceLoggerPlug
{
public:
    TraceLoggerPlug(const std::string& name) : plugin_name(name) { }
    virtual ~TraceLoggerPlug() = default;

    virtual void log(const char* msg, const char* name, uint8_t level, const char* trace_option, const Packet*) = 0;

    const std::string& get_name() const
    { return plugin_name; }

    void set_api(const TraceLogApi* p)
    { api = p; }

    const TraceLogApi* get_api() const
    { return api; }

    void set_ntuple(bool flag)
    { ntuple = flag; }

    void set_timestamp(bool flag)
    { timestamp = flag; }

    void set_enabled(bool flag)
    { enable = flag; }

    bool get_enabled() const
    { return enable; }

    bool get_ntuple() const
    { return ntuple; }

    bool get_timestamp() const
    { return timestamp; }

    char get_thread_type() const
    { return thread_type; }

    unsigned get_instance_id() const
    { return instance_id; }

    void set_thread_type(char t)
    {
        switch (t)
        {
        case STHREAD_TYPE_PACKET:
            thread_type = 'P';
            break;
        case STHREAD_TYPE_MAIN:
            thread_type = 'C';
            break;
        default:
            thread_type = 'O';
        }
    }

    void set_instance_id(unsigned id)
    { instance_id = id; }

protected:
    TraceLoggerPlug() = default;
    const TraceLogApi* api = nullptr;

private:
    std::string plugin_name;
    bool enable = false;    
    bool timestamp = false;
    bool ntuple = false;
    char thread_type = 'O';
    unsigned instance_id = 0;
};

typedef TraceLoggerPlug* (* TraceLogNewFunc)(class Module*, const std::string& name);
typedef void (* TraceLogDelFunc)(TraceLoggerPlug*);

struct TraceLogApi
{
    BaseApi base;
    unsigned flags;
    TraceLogNewFunc ctor;
    TraceLogDelFunc dtor;
};

}

#endif
