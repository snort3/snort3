//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// host_tracker.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_tracker.h"

using namespace snort;
using namespace std;

THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

bool HostTracker::add_service(Port port, IpProtocol proto, AppId appid, bool inferred_appid)
{
    host_tracker_stats.service_adds++;
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( auto& s : services )
    {
        if ( s.port == port and s.proto == proto )
        {
            if ( s.appid != appid and appid != APP_ID_NONE )
            {
                s.appid = appid;
                s.inferred_appid = inferred_appid;
            }
            return true;
        }
    }

    services.emplace_back( HostApplication{port, proto, appid, inferred_appid} );
    return true;
}

AppId HostTracker::get_appid(Port port, IpProtocol proto, bool inferred_only)
{
    host_tracker_stats.service_finds++;
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( const auto& s : services )
    {
        if ( s.port == port and s.proto == proto and
            (!inferred_only or s.inferred_appid == inferred_only) )
            return s.appid;
    }

    return APP_ID_NONE;
}

void HostTracker::stringify(string& str)
{
    if ( !services.empty() )
    {
        str += "\nservices size: " + to_string(services.size());
        for ( const auto& s : services )
        {
            str += "\n    port: " + to_string(s.port)
                + ", proto: " + to_string((uint8_t) s.proto);
            if ( s.appid != APP_ID_NONE )
            {
                str += ", appid: " + to_string(s.appid);
                if ( s.inferred_appid )
                    str += ", inferred";
            }
        }
   }
}
