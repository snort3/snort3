//--------------------------------------------------------------------------
// Copyright (C) 2015-2019 Cisco and/or its affiliates. All rights reserved.
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

// host_tracker.h author Steve Chew <stechew@cisco.com>

#ifndef HOST_TRACKER_H
#define HOST_TRACKER_H

// The HostTracker class holds information known about a host (may be from
// configuration or dynamic discovery).  It provides a thread-safe API to
// set/get the host data.

#include <mutex>
#include <vector>

#include "framework/counts.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "network_inspectors/appid/application_ids.h"
#include "protocols/protocol_ids.h"

struct HostTrackerStats
{
    PegCount service_adds;
    PegCount service_finds;
};

extern THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

struct HostApplication
{
    Port port;
    IpProtocol proto;
    AppId appid;
    bool inferred_appid;
};

class SO_PUBLIC HostTracker
{
public:
    // Appid may not be identified always. Inferred means dynamic/runtime
    // appid detected from one flow to another flow such as BitTorrent.
    bool add_service(Port port, IpProtocol proto,
        AppId appid = APP_ID_NONE, bool inferred_appid = false);

    AppId get_appid(Port port, IpProtocol proto, bool inferred_only = false);

    //  This should be updated whenever HostTracker data members are changed
    void stringify(std::string& str);

private:
    //  Ensure that updates to a shared object are safe
    std::mutex host_tracker_lock;

    std::vector<HostApplication> services;
};

#endif

