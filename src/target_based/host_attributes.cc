//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

// host_attributes.cc  author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_attributes.h"

#include "hash/lru_segmented_cache_shared.h"
#include "main/reload_tuner.h"
#include "main/shell.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread.h"

using namespace snort;

static const PegInfo host_attribute_pegs[] =
{
    { CountType::MAX, "total_hosts", "maximum number of entries in the host attribute table" },
    { CountType::SUM, "hosts_pruned", "number of LRU hosts pruned due to configured resource limits" },
    { CountType::SUM, "dynamic_host_adds", "number of host additions after initial host file load" },
    { CountType::SUM, "dynamic_service_adds", "number of service additions after initial host file load" },
    { CountType::SUM, "dynamic_service_updates", "number of service updates after initial host file load" },
    { CountType::SUM, "service_list_overflows", "number of service additions that failed due to configured resource limits" },
    { CountType::END, nullptr, nullptr }
};

template<typename Key, typename Value, typename Hash>
class HostLruSegmentedCache : public SegmentedLruCache<Key, Value, Hash>
{
public:

    HostLruSegmentedCache(const size_t initial_size, std::size_t seg_count = DEFAULT_SEGMENT_COUNT)
        : SegmentedLruCache<Key, Value, Hash>(initial_size, seg_count)
      { }
};

typedef HostLruSegmentedCache<snort::SfIp, HostAttributesDescriptor, HostAttributesCacheKey> HostAttributesSegmentedCache;

class HostAttributesReloadTuner : public snort::ReloadResourceTuner
{
public:
    HostAttributesReloadTuner() = default;

    bool tinit() override
    {
        HostAttributesManager::initialize();
        return true;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }
};

static THREAD_LOCAL HostAttributesSegmentedCache* active_cache = nullptr;
static HostAttributesSegmentedCache* swap_cache = nullptr;
static HostAttributesSegmentedCache* next_cache = nullptr;
static HostAttributesSegmentedCache* old_cache = nullptr;
static THREAD_LOCAL HostAttributeStats host_attribute_stats;

bool HostAttributesDescriptor::update_service
    (uint16_t port, uint16_t protocol, SnortProtocolId snort_protocol_id, bool& updated,
    bool is_appid_service)
{
    std::lock_guard<std::mutex> lck(host_attributes_lock);

    auto it = std::find_if(services.begin(), services.end(),
        [port, protocol](const HostServiceDescriptor& s){ return s.ipproto == protocol && s.port == port; });
    if (it != services.cend())
    {
        HostServiceDescriptor& s = *it;
        if ( s.snort_protocol_id != snort_protocol_id )
        {
            s.snort_protocol_id = snort_protocol_id;
            s.appid_service = is_appid_service;
        }
        updated = true;
        return true;
    }

    // service not found, add it
    if ( services.size() < SnortConfig::get_conf()->get_max_services_per_host() )
    {
        updated = false;
        services.emplace_back(HostServiceDescriptor(port, protocol, snort_protocol_id, is_appid_service));
        return true;
    }

    return false;
}

void HostAttributesDescriptor::clear_appid_services()
{
    std::lock_guard<std::mutex> lck(host_attributes_lock);
    for ( auto s = services.begin(); s != services.end(); )
    {
        if ( s->appid_service and s->snort_protocol_id != UNKNOWN_PROTOCOL_ID )
            s = services.erase(s);
        else
            s++;
    }
}

void HostAttributesDescriptor::get_host_attributes(uint16_t port,HostAttriInfo* host_info) const
{
    std::lock_guard<std::mutex> slk(host_attributes_lock);
    host_info->frag_policy = policies.fragPolicy;
    host_info->stream_policy = policies.streamPolicy;
    host_info->snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    auto it = std::find_if(services.cbegin(), services.cend(),
        [port](const HostServiceDescriptor &s){ return s.port == port; });
    if (it != services.cend())
        host_info->snort_protocol_id = (*it).snort_protocol_id;
}
bool HostAttributesManager::load_hosts_file(snort::SnortConfig* sc, const char* fname)
{
    delete next_cache;
    next_cache = new HostAttributesSegmentedCache(sc->max_attribute_hosts, sc->segment_count_host);

    Shell sh(fname);
    if ( sh.configure(sc, true) )
    {
        activate(sc);
        return true;
    }

    // loading of host file failed...
    load_failure_cleanup();
    return false;
}

bool HostAttributesManager::add_host(HostAttributesEntry host, snort::SnortConfig* sc)
{
    if ( !next_cache )
        next_cache = new HostAttributesSegmentedCache(sc->max_attribute_hosts, sc->segment_count_host);

    return next_cache->find_else_insert(host->get_ip_addr(), host, true);
}

void HostAttributesManager::activate(SnortConfig* sc)
{
    if ( next_cache == nullptr )
        return;
    old_cache = active_cache;
    active_cache = next_cache;
    swap_cache = next_cache;
    next_cache = nullptr;

    if( active_cache != old_cache and Snort::is_reloading() )
        sc->register_reload_handler(new HostAttributesReloadTuner);
}

void HostAttributesManager::initialize()
{ active_cache = swap_cache; }

void HostAttributesManager::load_failure_cleanup()
{
    delete next_cache;
    next_cache = nullptr;
}

void HostAttributesManager::swap_cleanup()
{
    delete old_cache;
    old_cache = nullptr;
}

void HostAttributesManager::term()
{ delete active_cache; }

bool HostAttributesManager::get_host_attributes(const snort::SfIp& host_ip, uint16_t port, HostAttriInfo* host_info)
{
    if ( !active_cache )
        return false;

    HostAttributesEntry h = active_cache->find(host_ip);
    if (h)
    {
        h->get_host_attributes(port, host_info);
        return true;
    }
    return false;
}

void HostAttributesManager::update_service(const snort::SfIp& host_ip, uint16_t port,
    uint16_t protocol, SnortProtocolId snort_protocol_id, bool is_appid_service)
{
    if ( active_cache )
    {
        bool created = false;
        HostAttributesEntry host = active_cache->find_else_create(host_ip, &created);
        if ( host )
        {
            if ( created )
            {
                host_attribute_stats.dynamic_host_adds++;
            }

            bool updated = false;
            if ( host->update_service(port, protocol, snort_protocol_id, updated, is_appid_service) )
            {
                if ( updated )
                    host_attribute_stats.dynamic_service_updates++;
                else
                    host_attribute_stats.dynamic_service_adds++;
            }
            else
                host_attribute_stats.service_list_overflows++;
        }
    }
}

void HostAttributesManager::clear_appid_services()
{
    if ( active_cache )
    {
        auto hosts = active_cache->get_all_data();
        for ( auto& h : hosts )
            h.second->clear_appid_services();
    }
}

int32_t HostAttributesManager::get_num_host_entries()
{
    if ( active_cache )
        return active_cache->size();

    return -1;
}

const PegInfo* HostAttributesManager::get_pegs()
{ return (const PegInfo*)&host_attribute_pegs; }

PegCount* HostAttributesManager::get_peg_counts()
{
    if ( active_cache )
    {
        const LruCacheSharedStats* cache_stats = (const LruCacheSharedStats*) active_cache->get_counts();
        host_attribute_stats.hosts_pruned = cache_stats->alloc_prunes;
        host_attribute_stats.total_hosts = active_cache->size();
    }

    return (PegCount*)&host_attribute_stats;
}

