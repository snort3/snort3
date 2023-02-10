//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

#include <cstring>
#include <mutex>
#include <list>
#include <set>
#include <unordered_set>
#include <vector>

#include "framework/counts.h"
#include "main/snort_types.h"
#include "main/thread.h"
#include "network_inspectors/appid/application_ids.h"
#include "protocols/protocol_ids.h"
#include "protocols/vlan.h"
#include "time/packet_time.h"

#include "cache_allocator.h"

struct HostTrackerStats
{
    PegCount service_adds;
    PegCount service_finds;
};

extern THREAD_LOCAL struct HostTrackerStats host_tracker_stats;

class RNAFlow;

namespace snort
{
#define INFO_SIZE 32
#define MAC_SIZE 6
extern const uint8_t zero_mac[MAC_SIZE];

struct HostMac
{
    HostMac() : ttl(0), primary(0), last_seen(0)
    { memset(mac, 0, MAC_SIZE); }

    HostMac(uint8_t p_ttl, const uint8_t* p_mac, uint8_t p_primary, uint32_t p_last_seen)
        : ttl(p_ttl), primary(p_primary), last_seen (p_last_seen) { memcpy(mac, p_mac, MAC_SIZE); }

    // the type and order below should match logger's serialization
    uint8_t ttl;
    uint8_t mac[MAC_SIZE];
    uint8_t primary;
    uint32_t last_seen;
};

struct HostApplicationInfo
{
    HostApplicationInfo() = default;
    HostApplicationInfo(const char *ver, const char *ven);
    char vendor[INFO_SIZE] = { '\0' };
    char version[INFO_SIZE] = { '\0' };

    friend class HostTracker;
private:
    bool visibility = true;
};

typedef HostCacheAllocIp<HostApplicationInfo> HostAppInfoAllocator;
typedef std::pair<AppId, bool> Payload_t;
typedef std::vector<Payload_t, HostCacheAllocIp<Payload_t>> PayloadVector;

struct HostApplication
{
    HostApplication() = default;
    HostApplication(Port pt, IpProtocol pr, AppId ap, bool in, uint32_t ht = 0, uint32_t ls = 0,
        bool banner = false) : port(pt), proto(pr), appid(ap), inferred_appid(in), hits(ht),
        last_seen(ls), banner_updated(banner) { }
    HostApplication(const HostApplication& ha): port(ha.port), proto(ha.proto), appid(ha.appid),
        inferred_appid(ha.inferred_appid), hits(ha.hits), last_seen(ha.last_seen),
        num_visible_payloads(ha.num_visible_payloads), info(ha.info), payloads(ha.payloads),
        visibility(ha.visibility) { }

    HostApplication& operator=(const HostApplication& ha)
    {
        port = ha.port;
        proto = ha.proto;
        appid = ha.appid;
        inferred_appid = ha.inferred_appid;
        hits = ha.hits;
        last_seen = ha.last_seen;
        info = ha.info;
        payloads = ha.payloads;
        visibility = ha.visibility;
        banner_updated = ha.banner_updated;
        num_visible_payloads = ha.num_visible_payloads;
        return *this;
    }

    Port port = 0;
    IpProtocol proto;
    AppId appid = APP_ID_NONE;
    bool inferred_appid = false;
    uint32_t hits = 0;
    uint32_t last_seen = 0;
    char user[INFO_SIZE] = { '\0' };
    uint8_t user_login = 0;
    bool banner_updated = false;
    size_t num_visible_payloads = 0;

    std::vector<HostApplicationInfo, HostAppInfoAllocator> info;
    PayloadVector payloads;

    friend class HostTracker;

// visibility is public in UT only, to avoid extra lock/unlock funcs used only by UT
#ifndef UNIT_TEST
private:
#endif
    bool visibility = true;

};

struct HostClient
{
    HostClient() = default;
    HostClient(AppId clientid, const char *ver, AppId ser);
    AppId id;
    char version[INFO_SIZE] = { '\0' };
    AppId service;
    PayloadVector payloads;
    size_t num_visible_payloads = 0;

    bool operator==(const HostClient& c) const
    {
        return id == c.id and service == c.service;
    }

    friend class HostTracker;

private:
    bool visibility = true;
};

struct DeviceFingerprint
{
    DeviceFingerprint(uint32_t id, uint32_t type, bool jb, const char* dev);
    uint32_t fpid;
    uint32_t fp_type;
    bool jail_broken;
    char device[INFO_SIZE] = { '\0' };
};

enum HostType : std::uint32_t
{
    HOST_TYPE_HOST = 0,
    HOST_TYPE_ROUTER,
    HOST_TYPE_BRIDGE,
    HOST_TYPE_NAT,
    HOST_TYPE_LB
};

class HostMac_t : public HostMac
{
public:
    HostMac_t(uint8_t p_ttl, const uint8_t* p_mac, uint8_t p_primary, uint32_t p_last_seen)
        : HostMac(p_ttl, p_mac, p_primary, p_last_seen) {}

    HostMac_t& operator=(const HostMac_t& hm)
    {
        ttl = hm.ttl;
        primary = hm.primary;
        last_seen = hm.last_seen;
        visibility = hm.visibility;
        memcpy(mac, hm.mac, MAC_SIZE);
        return *this;
    }

    bool visibility = true;
};

#define MIN_BOOT_TIME    10
#define MIN_TTL_DIFF     16

typedef HostCacheAllocIp<HostApplication> HostAppAllocator;
typedef HostCacheAllocIp<HostClient> HostClientAllocator;
typedef HostCacheAllocIp<DeviceFingerprint> HostDeviceFpAllocator;

class SO_PUBLIC HostTracker
{
public:

    typedef std::pair<uint16_t, bool> NetProto_t;
    typedef std::pair<uint8_t, bool> XProto_t;

    HostTracker();

    void update_last_seen();
    uint32_t get_last_seen() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_seen;
    }

    void update_last_event(uint32_t time = 0);
    uint32_t get_last_event() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return last_event;
    }

    std::vector<uint16_t> get_network_protos()
    {
        std::vector<uint16_t> out_protos;
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        for (const auto& proto : network_protos)
            if ( proto.second )
                out_protos.emplace_back(proto.first);
        return out_protos;
    }

    std::vector<uint16_t> get_xport_protos()
    {
        std::vector<uint16_t> out_protos;
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        for (const auto& proto : xport_protos)
            if ( proto.second )
                out_protos.emplace_back(proto.first);
        return out_protos;
    }

    void set_host_type(HostType rht)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        host_type = rht;
    }

    HostType get_host_type() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return host_type;
    }

    uint8_t get_hops()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return hops;
    }

    void update_hops(uint8_t h)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        hops = h;
    }

    bool add_client_payload(HostClient&, AppId, size_t);

    // Returns true if a new mac entry is added, false otherwise
    bool add_mac(const uint8_t* mac, uint8_t ttl, uint8_t primary);

    // Returns true if a mac entry TTL is updated and decreased, false otherwise
    bool update_mac_ttl(const uint8_t* mac, uint8_t new_ttl);

    // Returns true if we changed primary (false->true), false otherwise
    bool make_primary(const uint8_t* mac);

    // Returns true if a new payload entry added, false otherwise
    bool add_payload(HostApplication&, Port, IpProtocol, const AppId payload,
        const AppId service, size_t max_payloads);

    // Returns true after resetting hops if there is a primary mac
    bool reset_hops_if_primary();

    // Returns true and copy of the matching HostMac, false if no match...
    bool get_hostmac(const uint8_t* mac, HostMac& hm);

    const uint8_t* get_last_seen_mac(uint8_t*);

    void update_vlan(uint16_t vth_pri_cfi_vlan, uint16_t vth_proto);
    bool has_same_vlan(uint16_t);
    void get_vlan_details(uint8_t& cfi, uint8_t& priority, uint16_t& vid);

    // The caller owns and deletes the copied list of mac addresses
    void copy_data(uint8_t& p_hops, uint32_t& p_last_seen, std::list<HostMac>*& p_macs);

    bool add_network_proto(const uint16_t type);
    bool add_xport_proto(const uint8_t type);

    // Appid may not be identified always. Inferred means dynamic/runtime
    // appid detected from one flow to another flow such as BitTorrent.
    bool add_service(Port, IpProtocol,
        AppId appid = APP_ID_NONE, bool inferred_appid = false, bool* added = nullptr);
    bool add_service(const HostApplication&, bool* added = nullptr);
    void clear_service(HostApplication&);
    void update_service_port(HostApplication&, Port);
    void update_service_proto(HostApplication&, IpProtocol);

    AppId get_appid(Port, IpProtocol, bool inferred_only = false,
        bool allow_port_wildcard = false);

    size_t get_service_count();

    HostApplication add_service(Port, IpProtocol, uint32_t, bool&, AppId appid = APP_ID_NONE);

    void update_service(const HostApplication&);
    bool update_service_info(HostApplication&, const char* vendor, const char* version,
        uint16_t max_info);
    bool update_service_banner(Port, IpProtocol);
    bool update_service_user(Port, IpProtocol, const char* username, uint32_t lseen,
        uint16_t max_services, bool success);
    void remove_inferred_services();

    size_t get_client_count();
    HostClient find_or_add_client(AppId id, const char* version, AppId service,
        bool& is_new);
    bool add_tcp_fingerprint(uint32_t fpid);
    bool add_ua_fingerprint(uint32_t fpid, uint32_t fp_type, bool jail_broken,
        const char* device_info, uint8_t max_devices);
    bool add_udp_fingerprint(uint32_t fpid);
    bool add_smb_fingerprint(uint32_t fpid);

    bool add_cpe_os_hash(uint32_t hash);

    //  This should be updated whenever HostTracker data members are changed
    void stringify(std::string& str);

    uint8_t get_ip_ttl() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return ip_ttl;
    }

    void set_ip_ttl(uint8_t ttl)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        ip_ttl = ttl;
    }

    uint32_t get_nat_count_start() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return nat_count_start;
    }

    void set_nat_count_start(uint32_t natCountStart)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        nat_count_start = natCountStart;
    }

    uint32_t get_nat_count() const
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return nat_count;
    }

    void set_nat_count(uint32_t v = 0)
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        nat_count = v;
    }

    uint32_t inc_nat_count()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return ++nat_count;
    }

    bool set_netbios_name(const char*);

    bool set_visibility(bool v = true);

    bool is_visible() const;

    // the control delete commands do not actually remove objects from
    // the host tracker, but just mark them as invisible, until rediscovered.
    bool set_network_proto_visibility(uint16_t proto, bool v = true);
    bool set_xproto_visibility(uint8_t proto, bool v = true);
    bool set_service_visibility(Port, IpProtocol, bool v = true);
    bool set_client_visibility(const HostClient&, bool v = true);

#ifdef UNIT_TEST
    // Caller is responsible for checking visibility
    std::vector<HostApplication, HostAppAllocator> get_services()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return services;
    }

    // Caller is responsible for checking visibility
    std::vector<HostClient, HostClientAllocator> get_clients()
    {
        std::lock_guard<std::mutex> lck(host_tracker_lock);
        return clients;
    }
#endif

    void add_flow(RNAFlow*);
    void remove_flows();
    void remove_flow(RNAFlow*);

private:

    mutable std::mutex host_tracker_lock; // ensure that updates to a shared object are safe
    mutable std::mutex flows_lock;        // protect the flows set separately
    uint8_t hops;                 // hops from the snort inspector, e.g., zero for ARP
    uint32_t last_seen;           // the last time this host was seen
    uint32_t last_event;          // the last time an event was generated

    // list guarantees iterator validity on insertion
    std::list<HostMac_t, HostCacheAllocIp<HostMac_t>> macs;
    std::vector<NetProto_t, HostCacheAllocIp<NetProto_t>> network_protos;
    std::vector<XProto_t, HostCacheAllocIp<XProto_t>> xport_protos;
    std::vector<HostApplication, HostAppAllocator> services;
    std::vector<HostClient, HostClientAllocator> clients;
    std::set<uint32_t, std::less<uint32_t>, HostCacheAllocIp<uint32_t>> tcp_fpids;
    std::set<uint32_t, std::less<uint32_t>, HostCacheAllocIp<uint32_t>> udp_fpids;
    std::set<uint32_t, std::less<uint32_t>, HostCacheAllocIp<uint32_t>> smb_fpids;
    std::set<uint32_t, std::less<uint32_t>, HostCacheAllocIp<uint32_t>> cpe_fpids;
    std::vector<DeviceFingerprint, HostDeviceFpAllocator> ua_fps;
    std::string netbios_name;

    // flows that we belong to
    std::unordered_set<RNAFlow*> flows;

    bool vlan_tag_present = false;
    vlan::VlanTagHdr vlan_tag;
    HostType host_type = HOST_TYPE_HOST;
    uint8_t ip_ttl = 0;
    uint32_t nat_count = 0;
    uint32_t nat_count_start;     // the time nat counting starts for this host

    size_t visibility;

    uint32_t num_visible_services = 0;
    uint32_t num_visible_clients = 0;
    uint32_t num_visible_macs = 0;

    // These three do not lock independently; they are used by payload discovery and called
    // from add_payload(HostApplication&, Port, IpProtocol, AppId, AppId, size_t); where the
    // lock is actually obtained
    bool add_payload_no_lock(const AppId, HostApplication*, size_t);
    HostApplication* find_service_no_lock(Port, IpProtocol, AppId);
    void update_ha_no_lock(HostApplication& dst, HostApplication& src);

    HostApplication* find_and_add_service_no_lock(Port, IpProtocol, uint32_t lseen,
        bool& is_new, AppId, uint16_t max_services = 0);

    // Sets all payloads visible or invisible
    void set_payload_visibility_no_lock(PayloadVector& pv, bool v, size_t& num_vis);

    // Hide / delete the constructor from the outside world. We don't want to
    // have zombie host trackers, i.e. host tracker objects that live outside
    // the host cache.
    HostTracker( const HostTracker& ) = delete;
    HostTracker( const HostTracker&& ) = delete;

    HostTracker& operator=( const HostTracker& ) = delete;
    HostTracker& operator=( const HostTracker&& ) = delete;

    // Only the host cache can create them ...
    template<class Key, class Value, class Hash>
    friend class LruCacheShared;

    // ... and some unit tests. See Utest.h and UtestMacros.h in cpputest.
    friend class TEST_host_tracker_add_find_service_test_Test;
    friend class TEST_host_tracker_stringify_Test;
};
} // namespace snort
#endif
