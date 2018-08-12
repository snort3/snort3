//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
// Copyright (C) 2001-2004 Jeff Nathan <jeff@snort.org>
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

/* Snort ARPspoof Preprocessor Plugin
 *   by Jeff Nathan <jeff@snort.org>
 *   Version 0.1.4
 *
 * Purpose:
 *
 * This preprocessor looks for anomalies in ARP traffic and attempts to
 * maliciously overwrite  ARP cache information on hosts.
 *
 * Arguments:
 *
 * To check for unicast ARP requests use:
 * arpspoof: -unicast
 *
 * WARNING: this can generate false positives as Linux systems send unicast
 * ARP requests repetitively for entries in their cache.
 *
 * This plugin also takes a list of IP addresses and MAC address in the form:
 * arpspoof_detect_host: 10.10.10.10 29:a2:9a:29:a2:9a
 * arpspoof_detect_host: 192.168.40.1 f0:0f:00:f0:0f:00
 * and so forth...
 *
 * Effect:
 * By comparing information in the Ethernet header to the ARP frame, obvious
 * anomalies are detected.  Also, utilizing a user supplied list of IP
 * addresses and MAC addresses, ARP traffic appearing to have originated from
 * any IP in that list is carefully examined by comparing the source hardware
 * address to the user supplied hardware address.  If there is a mismatch, an
 * alert is generated as either an ARP request or REPLY can be used to
 * overwrite cache information on a remote host.  This should only be used for
 * hosts/devices on the **same layer 2 segment** !!
 *
 * Bugs:
 * This is a proof of concept ONLY.  It is clearly not complete.  Also, the
 * lookup function LookupIPMacEntryByIP is in need of optimization.  The
 * arpspoof_detect_host functionality may false alarm in redundant environments.
 * Also, see the comment above pertaining to Linux systems.
 *
 * Thanks:
 *
 * First and foremost Patrick Mullen who sat beside me and helped every step of
 * the way.  Andrew Baker for graciously supplying the tougher parts of this
 * code.  W. Richard Stevens for readable documentation and finally
 * Marty for being a badass.  All your packets are belong to Marty.
 *
 */

/*  I N C L U D E S  ************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/arp.h"
#include "protocols/eth.h"
#include "protocols/packet.h"
#include "protocols/wlan.h"
#include "sfip/sf_ip.h"

#include "arp_module.h"

using namespace snort;

static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

THREAD_LOCAL ProfileStats arpPerfStats;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------

static IPMacEntry* LookupIPMacEntryByIP(
    IPMacEntryList& ipmel, uint32_t ipv4_addr)
{
    for ( auto& p : ipmel )
    {
        if (p.ipv4_addr == ipv4_addr)
            return &p;
    }
    return nullptr;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class ArpSpoof : public Inspector
{
public:
    ArpSpoof(ArpSpoofModule*);
    ~ArpSpoof() override;

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    ArpSpoofConfig* config;
};

ArpSpoof::ArpSpoof(ArpSpoofModule* mod)
{
    config = mod->get_config();
}

ArpSpoof::~ArpSpoof ()
{
    delete config;
}

void ArpSpoof::show(SnortConfig*)
{
    LogMessage("arpspoof configured\n");

}

void ArpSpoof::eval(Packet* p)
{
    Profile profile(arpPerfStats);

    // precondition - what we registered for
    assert(p->proto_bits & PROTO_BIT__ARP);

    const uint8_t* dst_mac_addr;
    const uint8_t* src_mac_addr;

    if (p->proto_bits & PROTO_BIT__ETH)
    {
        const eth::EtherHdr* eh = layer::get_eth_layer(p);
        src_mac_addr = eh->ether_src;
        dst_mac_addr = eh->ether_dst;
    }
    else
    {
        const snort::wlan::WifiHdr* wifih = snort::layer::get_wifi_layer(p);
        if (wifih == nullptr)
            return;

        if ((wifih->frame_control & WLAN_FLAG_TODS) &&
             (wifih->frame_control & WLAN_FLAG_FROMDS))
         {
             dst_mac_addr = wifih->addr3;
             src_mac_addr = wifih->addr4;
         }
         else if (wifih->frame_control & WLAN_FLAG_TODS)
         {
             src_mac_addr = wifih->addr2;
             dst_mac_addr = wifih->addr3;
         }
         else if (wifih->frame_control & WLAN_FLAG_FROMDS)
         {
             dst_mac_addr = wifih->addr1;
             src_mac_addr = wifih->addr3;
         }
         else
         {
             dst_mac_addr = wifih->addr1;
             src_mac_addr = wifih->addr2;
         }
    }

    const snort::arp::EtherARP* ah = snort::layer::get_arp_layer(p);

    /* is the ARP protocol type IP and the ARP hardware type Ethernet? */
    if ((ntohs(ah->ea_hdr.ar_hrd) != 0x0001) ||
        (ntohs(ah->ea_hdr.ar_pro) != ETHERNET_TYPE_IP))
        return;

    ++asstats.total_packets;

    switch (ntohs(ah->ea_hdr.ar_op))
    {
    case ARPOP_REQUEST:
        if (memcmp((const uint8_t*)dst_mac_addr, (const uint8_t*)bcast, 6) != 0)
        {
            DetectionEngine::queue_event(GID_ARP_SPOOF, ARPSPOOF_UNICAST_ARP_REQUEST);
        }
        else if (memcmp((const uint8_t*)src_mac_addr,
            (const uint8_t*)ah->arp_sha, 6) != 0)
        {
            DetectionEngine::queue_event(GID_ARP_SPOOF, ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC);
        }
        break;
    case ARPOP_REPLY:
        if (memcmp((const uint8_t*)src_mac_addr,
            (const uint8_t*)ah->arp_sha, 6) != 0)
        {
            DetectionEngine::queue_event(GID_ARP_SPOOF, ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC);
        }
        else if (memcmp((const uint8_t*)dst_mac_addr,
            (const uint8_t*)ah->arp_tha, 6) != 0)
        {
            DetectionEngine::queue_event(GID_ARP_SPOOF, ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST);
        }
        break;
    }

    /* return if the overwrite list hasn't been initialized */
    if (!config->check_overwrite)
        return;

    IPMacEntry* ipme = LookupIPMacEntryByIP(config->ipmel, ah->arp_spa32);
    if ( ipme )
    {
        auto cmp_ether_src = memcmp(src_mac_addr, ipme->mac_addr, 6);
        auto cmp_arp_sha = memcmp(ah->arp_sha, ipme->mac_addr, 6);

        // If the Ethernet source address or the ARP source hardware address
        // in p doesn't match the MAC address in ipme, then generate an alert
        if ( cmp_ether_src || cmp_arp_sha )
        {
            DetectionEngine::queue_event(GID_ARP_SPOOF, ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK);
        }
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ArpSpoofModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* as_ctor(Module* m)
{
    return new ArpSpoof((ArpSpoofModule*)m);
}

static void as_dtor(Inspector* p)
{ delete p; }

static const InspectApi as_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_NETWORK,
    PROTO_BIT__ARP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    as_ctor,
    as_dtor,
    nullptr, // ssn
    nullptr, // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_arp_spoof[] =
#endif
{
    &as_api.base,
    nullptr
};
