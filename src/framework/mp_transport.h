//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// mp_transport.h author Oleksandr Stepanov <ostepano@cisco.com>

#ifndef MP_TRANSPORT_H
#define MP_TRANSPORT_H

#include "main/snort_types.h"
#include "framework/base_api.h"

#include <functional>
#include <string>

namespace snort
{

#define MP_TRANSPORT_API_VERSION ((BASE_API_VERSION << 16) | 1)

struct SnortConfig;
struct MPEventInfo;
struct MPHelperFunctions;

typedef std::function<void (const MPEventInfo& event_info)> TransportReceiveEventHandler;

enum MPTransportChannelStatus
{
    DISCONNECTED = 0,
    CONNECTING,
    CONNECTED,
    MAX
};

struct MPTransportChannelStatusHandle
{
    int id = 0;
    std::string name;
    MPTransportChannelStatus status = DISCONNECTED;

    const char* get_status_string() const
    {
        switch (status)
        {
            case DISCONNECTED: return "DISCONNECTED";
            case CONNECTING: return "CONNECTING";
            case CONNECTED: return "CONNECTED";
            default: return "UNKNOWN";
        }
    }
};

class MPTransport
{
    public:

    MPTransport() = default;
    virtual ~MPTransport() = default;

    virtual bool configure(const SnortConfig*) = 0;
    virtual void thread_init() = 0;
    virtual void thread_term() = 0;
    virtual void init_connection() = 0;
    virtual bool send_to_transport(MPEventInfo& event) = 0;
    virtual void register_event_helpers(const unsigned& pub_id, const unsigned& event_id, MPHelperFunctions& helper) = 0;
    virtual void register_receive_handler(const TransportReceiveEventHandler& handler) = 0;
    virtual void unregister_receive_handler() = 0;
    virtual void enable_logging() = 0;
    virtual void disable_logging() = 0;
    virtual bool is_logging_enabled() = 0;
    virtual MPTransportChannelStatusHandle* get_channel_status(unsigned& size) = 0;
};


typedef MPTransport* (* MPTransportNewFunc)(Module*);
typedef void (* MPTransportDelFunc)(MPTransport*);
typedef void (* MPTransportThreadInitFunc)(MPTransport*);
typedef void (* MPTransportThreadTermFunc)(MPTransport*);
typedef void (* MPTransportFunc)();

struct MPTransportApi
{
    BaseApi base;
    unsigned flags;

    MPTransportFunc pinit;     // plugin init
    MPTransportFunc pterm;     // cleanup pinit()
    MPTransportThreadInitFunc tinit;     // thread local init
    MPTransportThreadTermFunc tterm;     // cleanup tinit()

    MPTransportNewFunc ctor;
    MPTransportDelFunc dtor;
};

}
#endif // MP_TRANSPORT_H
