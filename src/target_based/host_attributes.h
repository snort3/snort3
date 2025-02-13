//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// host_attributes.h author davis mcpherson <davmcphe@cisco.com>

#ifndef HOST_ATTRIBUTES_H
#define HOST_ATTRIBUTES_H

// Provides attribute table initialization, lookup, swap, and releasing.

#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include "framework/counts.h"
#include "framework/decode_data.h"
#include "sfip/sf_ip.h"
#include "target_based/snort_protocols.h"

namespace snort
{
struct SnortConfig;
}

struct HostAttributeStats
{
    PegCount total_hosts = 0;
    PegCount hosts_pruned = 0;
    PegCount dynamic_host_adds = 0;
    PegCount dynamic_service_adds = 0;
    PegCount dynamic_service_updates = 0;
    PegCount service_list_overflows = 0;
};

class HostServiceDescriptor
{
public:
    HostServiceDescriptor() = default;
    HostServiceDescriptor(uint16_t port, uint16_t protocol, SnortProtocolId spi, bool appid_service)
        : port(port), ipproto(protocol), snort_protocol_id(spi), appid_service(appid_service)
    { }

    ~HostServiceDescriptor() = default;

    void reset()
    {
        port = 0;
        ipproto = 0;
        snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    }

    uint16_t port = 0;
    uint16_t ipproto = 0;
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    bool appid_service = false;
};

struct HostPolicyDescriptor
{
    uint8_t streamPolicy = 0;
    uint8_t fragPolicy = 0;
};

struct HostAttriInfo
{
    SnortProtocolId snort_protocol_id = UNKNOWN_PROTOCOL_ID;
    uint8_t stream_policy = 0;
    uint8_t frag_policy = 0;
};

class HostAttributesDescriptor
{
public:
    HostAttributesDescriptor() = default;
    ~HostAttributesDescriptor() = default;

    bool update_service(uint16_t port, uint16_t protocol, SnortProtocolId, bool& updated,
        bool is_appid_service = false);
    void clear_appid_services();
    void get_host_attributes(uint16_t protocol, uint16_t port, HostAttriInfo*) const;

    // Note: the following get/set are only called from main thread on a temp LRU table
    const snort::SfIp& get_ip_addr() const
    { return ip_address; }

    void set_ip_addr(const snort::SfIp& host_ip_addr)
    {
        ip_address = host_ip_addr;
    }

    void set_frag_policy(const uint8_t frag_policy)
    {
        policies.fragPolicy = frag_policy;
    }

    void set_stream_policy(uint8_t stream_policy)
    {
        policies.streamPolicy = stream_policy;
    }

private:
    mutable std::mutex host_attributes_lock; // ensure updates to this shared object are safe
    snort::SfIp ip_address;
    HostPolicyDescriptor policies;
    std::vector<HostServiceDescriptor> services;
};

typedef std::shared_ptr<HostAttributesDescriptor> HostAttributesEntry;

#define DEFAULT_MAX_ATTRIBUTE_HOSTS 10000
#define DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST 100
#define DEFAULT_MAX_METADATA_SERVICES 9

// Create a hash key from an IP address stored in a SfIp object.
struct HostAttributesCacheKey
{
    size_t operator()(const snort::SfIp& ip) const
    {
        const uint64_t* ip64 = (const uint64_t*) ip.get_ip6_ptr();
        return std::hash<uint64_t>() (ip64[0]) ^
               std::hash<uint64_t>() (ip64[1]);
    }
};

class HostAttributesManager
{
public:
    static bool load_hosts_file(snort::SnortConfig*, const char* fname);
    static void activate(snort::SnortConfig*);
    static void initialize();
    static void swap_cleanup();
    static void load_failure_cleanup();
    static void term();

    static bool add_host(HostAttributesEntry, snort::SnortConfig*);
    static bool get_host_attributes(const snort::SfIp&, uint16_t protocol, uint16_t port, HostAttriInfo*);
    static bool get_host_attributes(const snort::SfIp&, PktType pkt_type, uint16_t port, HostAttriInfo*);
    static void update_service(const snort::SfIp&, uint16_t port, uint16_t protocol,
        SnortProtocolId, bool is_appid_service = false);
    static void clear_appid_services();
    static int32_t get_num_host_entries();
    static const PegInfo* get_pegs();
    static PegCount* get_peg_counts();
};

#endif
