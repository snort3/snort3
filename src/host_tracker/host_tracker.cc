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

snort::SfIp HostTracker::get_ip_addr()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    return ip_addr;
}

void HostTracker::set_ip_addr(const snort::SfIp& new_ip_addr)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    std::memcpy(&ip_addr, &new_ip_addr, sizeof(ip_addr));
}

Policy HostTracker::get_stream_policy()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    return stream_policy;
}

void HostTracker::set_stream_policy(const Policy& policy)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    stream_policy = policy;
}

Policy HostTracker::get_frag_policy()
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    return frag_policy;
}

void HostTracker::set_frag_policy(const Policy& policy)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    frag_policy = policy;
}

void HostTracker::add_app_mapping(Port port, Protocol proto, AppId appid)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    AppMapping app_map = {port, proto, appid};

    app_mappings.emplace_back(app_map);
}

AppId HostTracker::find_app_mapping(Port port, Protocol proto)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    for (std::vector<AppMapping>::iterator it=app_mappings.begin(); it!=app_mappings.end(); ++it)
    {
        if (it->port == port and it->proto ==proto)
        {
            return it->appid;
        }
    }
    return APP_ID_NONE;
}

bool HostTracker::find_else_add_app_mapping(Port port, Protocol proto, AppId appid)
{
    std::lock_guard<std::mutex> lck(host_tracker_lock);
    for (std::vector<AppMapping>::iterator it=app_mappings.begin(); it!=app_mappings.end(); ++it)
    {
        if (it->port == port and it->proto ==proto)
        {
            return false;
        }
    }
    AppMapping app_map = {port, proto, appid};

    app_mappings.emplace_back(app_map);
    return true;
}

bool HostTracker::add_service(const HostApplicationEntry& app_entry)
{
    host_tracker_stats.service_adds++;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    auto iter = std::find(services.begin(), services.end(), app_entry);
    if (iter != services.end())
        return false;   //  Already exists.

    services.emplace_front(app_entry);
    return true;
}

void HostTracker::add_or_replace_service(const HostApplicationEntry& app_entry)
{
    host_tracker_stats.service_adds++;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    auto iter = std::find(services.begin(), services.end(), app_entry);
    if (iter != services.end())
        services.erase(iter);

    services.emplace_front(app_entry);
}

bool HostTracker::find_service(Protocol ipproto, Port port, HostApplicationEntry& app_entry)
{
    HostApplicationEntry tmp_entry(ipproto, port, UNKNOWN_PROTOCOL_ID);
    host_tracker_stats.service_finds++;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    auto iter = std::find(services.begin(), services.end(), tmp_entry);
    if (iter != services.end())
    {
        app_entry = *iter;
        return true;
    }

    return false;
}

bool HostTracker::remove_service(Protocol ipproto, Port port)
{
    HostApplicationEntry tmp_entry(ipproto, port, UNKNOWN_PROTOCOL_ID);
    host_tracker_stats.service_removes++;

    std::lock_guard<std::mutex> lck(host_tracker_lock);

    auto iter = std::find(services.begin(), services.end(), tmp_entry);
    if (iter != services.end())
    {
        services.erase(iter);
        return true;   //  Assumes only one matching entry.
    }

    return false;
}

void HostTracker::stringify(string& str)
{
    str = "IP: ";
    SfIpString ip_str;
    str += ip_addr.ntop(ip_str);

    if ( !app_mappings.empty() )
    {
        str += "\napp_mappings size: " + to_string(app_mappings.size());
        for ( const auto& elem : app_mappings )
            str += "\n    port: " + to_string(elem.port)
                + ", proto: " + to_string(elem.proto)
                + ", appid: " + to_string(elem.appid);
    }

    if ( stream_policy or frag_policy )
        str += "\nstream policy: " + to_string(stream_policy)
            + ", frag policy: " + to_string(frag_policy);

    if ( !services.empty() )
    {
        str += "\nservices size: " + to_string(services.size());
        for ( const auto& elem : services )
            str += "\n    port: " + to_string(elem.port)
                + ", proto: " + to_string(elem.ipproto)
                + ", snort proto: " + to_string(elem.snort_protocol_id);
    }
}
