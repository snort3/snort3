//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef RNA_LOGGER_H
#define RNA_LOGGER_H

#include "host_tracker/host_cache.h"
#include "host_tracker/host_tracker.h"
#include "rna_cpe_os.h"
#include "rna_tracker.h"

namespace snort
{
struct Packet;
class FpFingerprint;
}

class RnaLogger
{
public:
    RnaLogger(const bool enable) : enabled(enable) { }

    // for host application
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, const snort::HostApplication* ha);

    // for host client
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, const snort::HostClient* hcp);

    // for host user
    void log(uint16_t type, uint16_t subtype, const snort::Packet*, RnaTracker*,
        const struct in6_addr*, const char* user, AppId appid, uint32_t event_time);

    // for cpe os info event
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, const snort::FpFingerprint* fp,
        const std::vector<const char*>* cpeos, uint32_t event_time);

    // for fingerprint
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, const snort::FpFingerprint* fp,
        uint32_t event_time, const char* device_info = nullptr, bool jail_broken = false);

    // for event time
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, uint32_t event_time);

    // for mac event
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac,
        const snort::HostMac* hm = nullptr, uint32_t event_time = 0);

    // for protocol event
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        uint16_t proto, const uint8_t* mac, const struct in6_addr* ip = nullptr,
        uint32_t event_time = 0);

    // for timeout update
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, const uint8_t* src_mac,
        const struct in6_addr* src_ip, RnaTracker* ht, uint32_t event_time, void* cond_var);

    // for dhcp info event
    void log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
        const struct in6_addr* src_ip, const uint8_t* src_mac, uint32_t lease, uint32_t netmask,
        const struct in6_addr* router);

    // for all
    bool log(uint16_t type, uint16_t subtype, const struct in6_addr* src_ip,
        const uint8_t* src_mac, RnaTracker* ht, const snort::Packet* p = nullptr,
        uint32_t event_time = 0, uint16_t proto = 0, const snort::HostMac* hm = nullptr,
        const snort::HostApplication* ha = nullptr, const snort::FpFingerprint* fp = nullptr,
        void* cond_var = nullptr, const snort::HostClient* hc = nullptr,
        const char* user = nullptr, AppId appid = APP_ID_NONE, const char* device_info = nullptr,
        bool jail_broken = false, uint32_t lease = 0, uint32_t netmask = 0,
        const struct in6_addr* router = nullptr, const char* nb_name = nullptr,
        const std::vector<const char*>* cpeos = nullptr);

private:
    const bool enabled;
};

#endif
