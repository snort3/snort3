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

    macs.emplace_back(ttl, mac, primary, last_seen);
    return true;
}

const HostMac* HostTracker::get_hostmac(const uint8_t* mac)
{
    if ( !mac or !memcmp(mac, zero_mac, MAC_SIZE) )
        return nullptr;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( const auto& hm : macs )
        if ( !memcmp(mac, hm.mac, MAC_SIZE) )
            return &hm;

    return nullptr;
}

bool HostTracker::update_mac_ttl(const uint8_t* mac, uint8_t new_ttl)
{
    if ( !mac or !memcmp(mac, zero_mac, MAC_SIZE) )
        return false;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( auto& hm : macs )
        if ( !memcmp(mac, hm.mac, MAC_SIZE) )
        {
            if (hm.ttl < new_ttl)
            {
                hm.ttl = new_ttl;
                return true;
            }

            return false;
        }

    return false;
}

bool HostTracker::make_primary(const uint8_t* mac)
{
    if ( !mac or !memcmp(mac, zero_mac, MAC_SIZE) )
        return false;

    HostMac* hm = nullptr;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    for ( auto& hm_iter : macs )
        if ( !memcmp(mac, hm_iter.mac, MAC_SIZE) )
        {
            hm = &hm_iter;
            break;
        }

    if ( !hm )
        return false;

    if (!hm->primary)
    {
        hm->primary = true;
        return true;
    }

    return false;
}

HostMac* HostTracker::get_max_ttl_hostmac()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);

    HostMac* max_ttl_hm = nullptr;
    uint8_t max_ttl = 0;

    for ( auto& hm : macs )
    {
        if (hm.primary)
            return &hm;

        if (hm.ttl > max_ttl)
        {
            max_ttl = hm.ttl;
            max_ttl_hm = &hm;
        }
    }

    return max_ttl_hm;
}

void HostTracker::update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto)
{
    vlan_tag_present = true;
    vlan_tag.vth_pri_cfi_vlan = vth_pri_cfi_vlan;
    vlan_tag.vth_proto = vth_proto;
}

bool HostTracker::has_vlan()
{
    return vlan_tag_present;
}

uint16_t HostTracker::get_vlan()
{
    return vlan_tag.vth_pri_cfi_vlan;
}

void HostTracker::get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid)
{
    cfi = vlan_tag.cfi();
    priority = vlan_tag.priority();
    vid = vlan_tag.vid();
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

void HostTracker::remove_inferred_services()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    for ( auto s = services.begin(); s != services.end(); )
    {
        if (s->inferred_appid)
            s = services.erase(s);
        else
            s++;
    }
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
