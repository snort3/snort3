//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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
#include "host_cache_allocator.cc"

#include "utils/util.h"

using namespace snort;
using namespace std;

THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

const uint8_t snort::zero_mac[MAC_SIZE] = {0, 0, 0, 0, 0, 0};

void HostTracker::update_last_seen()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    last_seen = (uint32_t) packet_time();
}

void HostTracker::update_last_event(uint32_t time)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    last_event = time ? time : last_seen;
}

bool HostTracker::add_mac(const uint8_t* mac, uint8_t ttl, uint8_t primary)
{
    if ( !mac or !memcmp(mac, zero_mac, MAC_SIZE) )
        return false;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( auto& hm : macs )
        if ( !memcmp(mac, hm.mac, MAC_SIZE) )
            return false;

    if ( primary )
    {
        // only one primary mac (e.g., from ARP) is maintained at the front
        if ( !macs.empty() )
            macs.front().primary = 0;
        macs.emplace_front(ttl, mac, primary, last_seen);
    }
    else
        macs.emplace_back(ttl, mac, primary, last_seen);
    return true;
}

void HostTracker::copy_data(uint8_t& p_hops, uint32_t& p_last_seen, list<HostMac>*& p_macs)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    p_hops = hops;
    p_last_seen = last_seen;
    if ( !macs.empty() )
        p_macs = new list<HostMac>(macs.begin(), macs.end());
}

bool HostTracker::add_service(Port port, IpProtocol proto, AppId appid, bool inferred_appid, bool* added)
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
                if (added)
                    *added = true;
            }
            return true;
        }
    }

    services.emplace_back( HostApplication{port, proto, appid, inferred_appid} );
    if (added)
        *added = true;

    return true;
}

AppId HostTracker::get_appid(Port port, IpProtocol proto, bool inferred_only, bool allow_port_wildcard)
{
    host_tracker_stats.service_finds++;
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( const auto& s : services )
    {
        bool matched = (s.port == port and s.proto == proto and (!inferred_only or s.inferred_appid == inferred_only));
        if ( matched or ( allow_port_wildcard and s.inferred_appid ) )
            return s.appid;
    }

    return APP_ID_NONE;
}

static inline string to_time_string(uint32_t p_time)
{
    time_t raw_time = (time_t) p_time;
    struct tm* timeinfo = gmtime(&raw_time);
    char buffer[30];
    strftime(buffer, 30, "%F %T", timeinfo);
    return buffer;
}

static inline string to_mac_string(const uint8_t* mac)
{
    char mac_addr[18];
    snprintf(mac_addr, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_addr;
}

void HostTracker::stringify(string& str)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    str += "\n    hops: " + to_string(hops) + ", time: " + to_time_string(last_seen);

    if ( !macs.empty() )
    {
        str += "\nmacs size: " + to_string(macs.size());
        for ( const auto& m : macs )
        {
            str += "\n    mac: " + to_mac_string(m.mac)
                + ", ttl: " + to_string(m.ttl)
                + ", primary: " + to_string(m.primary)
                + ", time: " + to_time_string(m.last_seen);
        }
    }

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
