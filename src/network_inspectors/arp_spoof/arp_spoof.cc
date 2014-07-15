/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2004-2013 Sourcefire, Inc.
** Copyright (C) 2001-2004 Jeff Nathan <jeff@snort.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
 * ARP requests repetatively for entries in their cache.
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

#include <assert.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "snort_types.h"
#include "snort_debug.h"
#include "detect.h"
#include "protocols/packet.h"
#include "event.h"
#include "parser.h"
#include "mstring.h"
#include "util.h"

#include "snort.h"
#include "profiler.h"

#include "arp_module.h"
#include "framework/inspector.h"
#include "protocols/layer.h"
#include "protocols/arp.h"

static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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

#ifdef DEBUG
static void PrintIPMacEntryList(IPMacEntryList& ipmel)
{
    if ( !ipmel.size() )
        return;

    LogMessage("Arpspoof IPMacEntry List");
    LogMessage("  Size: %ld\n", ipmel.size());

    for ( auto p : ipmel )
    {
        snort_ip in;
        sfip_set_raw(&in, &p.ipv4_addr, AF_INET);
        // FIXIT replace all inet_ntoa() with thread safe
        LogMessage("    %s -> ", inet_ntoa(IP_ARG(in)));

        for (int i = 0; i < 6; i++)
        {
            LogMessage("%02x", p.mac_addr[i]);
            if (i != 5)
                LogMessage(":");
        }
        LogMessage("\n");
    }
}
#endif

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class ArpSpoof : public Inspector {
public:
    ArpSpoof(ArpSpoofModule*);
    ~ArpSpoof();

    void show(SnortConfig*);
    void eval(Packet*);

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

#if defined(DEBUG)
    PrintIPMacEntryList(config->ipmel);
#endif
}

void ArpSpoof::eval(Packet *p)
{
    IPMacEntry *ipme;
    PROFILE_VARS;
    const arp::EtherARP *ah;
    const eth::EtherHdr *eh;

    // preconditions - what we registered for
    assert((p->proto_bits & PROTO_BIT__ETH) && (p->proto_bits & PROTO_BIT__ARP));

    ah = layer::get_arp_layer(p);
    eh = layer::get_eth_layer(p);

    /* is the ARP protocol type IP and the ARP hardware type Ethernet? */
    if ((ntohs(ah->ea_hdr.ar_hrd) != 0x0001) ||
            (ntohs(ah->ea_hdr.ar_pro) != ETHERNET_TYPE_IP))
        return;

    PREPROC_PROFILE_START(arpPerfStats);
    ++asstats.total_packets;

    switch(ntohs(ah->ea_hdr.ar_op))
    {
        case ARPOP_REQUEST:
            if (config->check_unicast_arp)
            {
                if (memcmp((u_char *)eh->ether_dst, (u_char *)bcast, 6) != 0)
                {
                    SnortEventqAdd(GID_ARP_SPOOF,
                            ARPSPOOF_UNICAST_ARP_REQUEST);

                    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                            "MODNAME: Unicast request\n"););
                }
            }
            else if (memcmp((u_char *)eh->ether_src,
                    (u_char *)ah->arp_sha, 6) != 0)
            {
                SnortEventqAdd(GID_ARP_SPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                            "MODNAME: Ethernet/ARP mismatch request\n"););
            }
            break;
        case ARPOP_REPLY:
            if (memcmp((u_char *)eh->ether_src,
                    (u_char *)ah->arp_sha, 6) != 0)
            {
                SnortEventqAdd(GID_ARP_SPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                        "MODNAME: Ethernet/ARP mismatch reply src\n"););
            }
            else if (memcmp((u_char *)eh->ether_dst,
                    (u_char *)ah->arp_tha, 6) != 0)
            {
                SnortEventqAdd(GID_ARP_SPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                        "MODNAME: Ethernet/ARP mismatch reply dst\n"););
            }
            break;
    }
    PREPROC_PROFILE_END(arpPerfStats);

    /* return if the overwrite list hasn't been initialized */
    if (!config->check_overwrite)
        return;

    if ((ipme = LookupIPMacEntryByIP(config->ipmel,
                                     *(uint32_t *)&ah->arp_spa)) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                "MODNAME: LookupIPMacEntryByIp returned NULL\n"););
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                "MODNAME: LookupIPMacEntryByIP returned %p\n", ipme););

        /* If the Ethernet source address or the ARP source hardware address
         * in p doesn't match the MAC address in ipme, then generate an alert
         */
        if ((memcmp((uint8_t *)eh->ether_src,
                (uint8_t *)ipme->mac_addr, 6)) ||
                (memcmp((uint8_t *)ah->arp_sha,
                (uint8_t *)ipme->mac_addr, 6)))
        {
            SnortEventqAdd(GID_ARP_SPOOF,
                    ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK);

            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                    "MODNAME: Attempted ARP cache overwrite attack\n"););

            return;
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
        MOD_NAME,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_PROTOCOL, 
    PROTO_BIT__ARP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    as_ctor,
    as_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // ssn
    nullptr, // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &as_api.base,
    nullptr
};
#else
const BaseApi* nin_arp_spoof = &as_api.base;
#endif

