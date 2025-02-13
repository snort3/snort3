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

#ifndef RNA_LOGGER_EVENT_H
#define RNA_LOGGER_EVENT_H

#include "events/event.h"
#include "host_tracker/host_cache.h"
#include "host_tracker/host_tracker.h"
#include "rna_cpe_os.h"
#include "rna_tracker.h"

namespace snort
{
struct Packet;
class FpFingerprint;
}

struct RnaLoggerEvent : public Event
{
    RnaLoggerEvent (uint16_t t, uint16_t st, const uint8_t* mc, const RnaTracker* rt,
        const snort::HostMac* hmp, uint16_t pr, void* cv, const snort::HostApplication* hap,
        const snort::FpFingerprint* fpr, const snort::HostClient* hcp, const char* u,
        int32_t app, const char* di, bool jb, uint32_t ls, uint32_t nm,
        const struct in6_addr* rtr, const snort::Packet* p, const char* nb_name,
        const std::vector<const char*>* cpe) :

        type(t), subtype(st), mac(mc), ht(rt), hm(hmp), proto(pr), cond_var(cv), ha(hap),
        fp(fpr), hc(hcp), user(u), appid(app), device_info(di), jail_broken(jb), lease(ls),
        netmask(nm), router(rtr), pkt(p), netbios_name(nb_name), cpe_os(cpe) { }

    uint32_t event_time = 0;
    uint16_t type;
    uint16_t subtype;
    const struct in6_addr* ip = nullptr;
    const uint8_t* mac;
    const RnaTracker* ht;
    const snort::HostMac* hm;
    uint16_t proto;
    void* cond_var;
    const snort::HostApplication* ha;
    const snort::FpFingerprint* fp;
    const snort::HostClient* hc;
    const char* user;
    AppId appid;
    const char* device_info;
    bool jail_broken;
    uint32_t lease;
    uint32_t netmask;
    const struct in6_addr* router;
    const snort::Packet* pkt;
    const char* netbios_name = nullptr;
    const std::vector<const char*>* cpe_os = nullptr;
};

#endif
