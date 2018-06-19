//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_bootp.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_bootp.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_inspector.h"
#include "appid_utils/ip_funcs.h"
#include "protocols/eth.h"
#include "protocols/packet.h"

using namespace snort;

#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OPTION55_LEN_MAX 255

#pragma pack(1)

struct ServiceBOOTPHeader
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
};

enum DHCP_OPTIONS
{
    DHCP_OPT_SUBNET_MASK = 1,
    DHCP_OPT_ROUTER = 3,
    DHCP_OPT_DOMAIN_NAME_SERVER = 6,
    DHCP_OPT_DOMAIN_NAME = 15,
    DHCP_OPT_IPADDR_LEASE_TIME = 51,
    DHCP_OPT_DHCP_MESSAGE_TYPE =53
};

struct ServiceDHCPOption
{
    uint8_t option;
    uint8_t len;
};

#pragma pack()

static const uint8_t zeromac[6] = { 0, 0, 0, 0, 0, 0 };
static THREAD_LOCAL DHCPInfo* dhcp_info_free_list = nullptr;

BootpServiceDetector::BootpServiceDetector(ServiceDiscovery* sd)
{
    handler = sd;
    name = "bootp";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_DHCP, APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED }
    };

    service_ports =
    {
        { 67, IpProtocol::UDP, false },
        { 67, IpProtocol::UDP, true },
    };

    handler->register_detector(name, this, proto);
}

BootpServiceDetector::~BootpServiceDetector()
{
    release_thread_resources();
}

void BootpServiceDetector::release_thread_resources()
{
    DHCPInfo* info;

    while ((info = dhcp_info_free_list))
    {
        dhcp_info_free_list = info->next;
        snort_free(info);
    }
}

int BootpServiceDetector::validate(AppIdDiscoveryArgs& args)
{
    const ServiceBOOTPHeader* bh;
    const ServiceDHCPOption* op;
    unsigned i;
    unsigned op55_len=0;
    unsigned op60_len=0;
    const uint8_t* op55=nullptr;
    const uint8_t* op60=nullptr;
    const uint8_t* data = args.data;
    Packet* pkt = args.pkt;
    uint16_t size = args.size;

    if (!size)
        goto inprocess;

    if (size < sizeof(ServiceBOOTPHeader))
        goto fail;

    bh = (const ServiceBOOTPHeader*)data;

    if (bh->htype != 0x01)
        goto fail;
    if (bh->hlen != 0x06)
        goto fail;

    for (i=0; i<sizeof(bh->sname); i++)
    {
        if (!bh->sname[i])
            break;
    }
    if (i >= sizeof(bh->sname))
        goto fail;

    for (i=0; i<sizeof(bh->file); i++)
    {
        if (!bh->file[i])
            break;
    }
    if (i >= sizeof(bh->file))
        goto fail;

    if (bh->op == 0x01)
    {
        if (size > sizeof(ServiceBOOTPHeader) + 4)
        {
            if (ntohl(*((const uint32_t*)(data + sizeof(ServiceBOOTPHeader)))) ==
                DHCP_MAGIC_COOKIE)
            {
                int option53 = 0;
                for (i=sizeof(ServiceBOOTPHeader)+sizeof(uint32_t); i<size; )
                {
                    op = (const ServiceDHCPOption*)&data[i];
                    if (op->option == 0xff)
                    {
                        const eth::EtherHdr* eh = layer::get_eth_layer(pkt);

                        if (!eh)
                            goto fail;

                        if (option53 && op55_len && (memcmp(eh->ether_src, bh->chaddr, 6) == 0))
                        {
                            if (add_dhcp_info(args.asd, op55_len, op55, op60_len, op60, bh->chaddr))
                                return APPID_ENOMEM;
                        }
                        goto inprocess;
                    }
                    i += sizeof(ServiceDHCPOption);
                    if (i >= size)
                        goto not_compatible;
                    if (op->option == 53 && op->len == 1 && i + 1 < size && data[i] == 3)
                    {
                        option53 = 1;
                    }
                    else if (op->option == 55 && op->len >= 1)
                    {
                        if (option53)
                        {
                            op55_len = op->len;
                            op55 = &data[i];
                        }
                    }
                    else if (op->option == 60 && op->len >= 1)
                    {
                        if (option53)
                        {
                            op60_len = op->len;
                            op60 = &data[i];
                        }
                    }
                    i += op->len;
                    if (i >= size)
                        goto not_compatible;
                }
                goto not_compatible;
            }
        }
        goto not_compatible;
    }

    if (bh->op != 0x02)
        goto fail;

    if (args.dir == APP_ID_FROM_INITIATOR)
        args.asd.set_session_flags(APPID_SESSION_UDP_REVERSED);
    else
        args.asd.clear_session_flags(APPID_SESSION_UDP_REVERSED);

    if (size > sizeof(ServiceBOOTPHeader) + 4)
    {
        if (ntohl(*((const uint32_t*)(data + sizeof(ServiceBOOTPHeader)))) ==
            DHCP_MAGIC_COOKIE)
        {
            int option53 = 0;
            uint32_t subnet = 0;
            uint32_t router = 0;
            uint32_t leaseTime = 0;

            for (i=sizeof(ServiceBOOTPHeader)+sizeof(uint32_t);
                i<size;
                )
            {
                op = (const ServiceDHCPOption*)&data[i];
                if (op->option == 0xff)
                {
                    const eth::EtherHdr* eh = layer::get_eth_layer(pkt);

                    if (!eh)
                        goto fail;

                    if (option53 && (memcmp(eh->ether_dst, bh->chaddr, 6) == 0))
                        add_new_dhcp_lease(args.asd, bh->chaddr, bh->yiaddr, pkt->pkth->ingress_group,
                            ntohl(subnet), ntohl(leaseTime),
                            router);
                    goto success;
                }
                i += sizeof(ServiceDHCPOption);
                if (i + op->len > size)
                    goto fail;

                switch (op->option)
                {
                case DHCP_OPT_DHCP_MESSAGE_TYPE:
                    if (op->len == 1 && data[i] == 5)
                    {
                        option53 = 1;
                    }
                    break;
                case DHCP_OPT_SUBNET_MASK:
                    if (op->len == 4)
                    {
                        memcpy(&subnet, &data[i], sizeof(subnet));
                    }
                    break;
                case DHCP_OPT_ROUTER:
                    if (op->len == 4)
                    {
                        memcpy(&router, &data[i], sizeof(router));
                    }
                    break;
                case DHCP_OPT_IPADDR_LEASE_TIME:
                    if (op->len == 4 )
                    {
                        memcpy(&leaseTime, &data[i], sizeof(leaseTime));
                    }
                    break;
                default:
                    ;
                }
                i += op->len;
                if (i >= size)
                    goto fail;
            }
            goto fail;
        }
    }

success:
    if (!args.asd.is_service_detected())
    {
        args.asd.set_session_flags(APPID_SESSION_CONTINUE);
        add_service(args.asd, args.pkt, args.dir, APP_ID_DHCP);
    }
    return APPID_SUCCESS;

inprocess:
    if (!args.asd.is_service_detected())
    {
        service_inprocess(args.asd, args.pkt, args.dir);
    }
    return APPID_INPROCESS;

fail:
    if (!args.asd.is_service_detected())
    {
        fail_service(args.asd, args.pkt, args.dir);
    }
    args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
    return APPID_NOMATCH;

not_compatible:
    if (!args.asd.is_service_detected())
    {
        incompatible_data(args.asd, args.pkt, args.dir);
    }
    return APPID_NOT_COMPATIBLE;
}

void BootpServiceDetector::AppIdFreeDhcpData(DHCPData* dd)
{
    snort_free(dd);
}

void BootpServiceDetector::AppIdFreeDhcpInfo(DHCPInfo* dd)
{
    if (dd)
    {
        dd->next = dhcp_info_free_list;
        dhcp_info_free_list = dd;
    }
}

int BootpServiceDetector::add_dhcp_info(AppIdSession& asd, unsigned op55_len, const uint8_t* op55,
    unsigned op60_len, const uint8_t* op60, const uint8_t* mac)
{
    if (op55_len && op55_len <= DHCP_OPTION55_LEN_MAX
        && !asd.get_session_flags(APPID_SESSION_HAS_DHCP_FP))
    {
        DHCPData* rdd = (DHCPData*)snort_calloc(sizeof(*rdd));
        if (asd.add_flow_data(rdd, APPID_SESSION_DATA_DHCP_FP_DATA,
            (AppIdFreeFCN)BootpServiceDetector::AppIdFreeDhcpData))
        {
            BootpServiceDetector::AppIdFreeDhcpData(rdd);
            return -1;
        }

        asd.set_session_flags(APPID_SESSION_HAS_DHCP_FP);
        rdd->op55_len = (op55_len > DHCP_OP55_MAX_SIZE) ? DHCP_OP55_MAX_SIZE : op55_len;
        memcpy(rdd->op55, op55, rdd->op55_len);
        rdd->op60_len =  (op60_len > DHCP_OP60_MAX_SIZE) ? DHCP_OP60_MAX_SIZE : op60_len;
        if (op60_len)
            memcpy(rdd->op60, op60, rdd->op60_len);
        memcpy(rdd->eth_addr, mac, sizeof(rdd->eth_addr));
    }
    return 0;
}

#ifdef USE_RNA_CONFIG
static unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone)
{
    NetworkSet* net_list;
    unsigned flags;
    AppIdConfig* config = AppIdInspector::get_inspector()->get_appid_config();

    if (zone >= 0 && zone < MAX_ZONES && config->net_list_by_zone[zone])
        net_list = config->net_list_by_zone[zone];
    else
        net_list = config->net_list;

    NetworkSetManager::contains_ex(net_list, ip4, &flags);
    return flags;
}

#else
static unsigned isIPv4HostMonitored(uint32_t, int32_t)
{
    // FIXIT-M Defaulting to checking everything everywhere until RNA config is reimplemented
    return IPFUNCS_HOSTS_IP | IPFUNCS_USER_IP | IPFUNCS_APPLICATION;
}

#endif

void BootpServiceDetector::add_new_dhcp_lease(AppIdSession& asd, const uint8_t* mac, uint32_t ip,
    int32_t zone,
    uint32_t subnetmask, uint32_t leaseSecs, uint32_t router)
{
    DHCPInfo* info;

    if (memcmp(mac, zeromac, 6) == 0 || ip == 0)
        return;

    if (!asd.get_session_flags(APPID_SESSION_DO_RNA)
        || asd.get_session_flags(APPID_SESSION_HAS_DHCP_INFO))
        return;

    unsigned flags = isIPv4HostMonitored(ntohl(ip), zone);
    if (!(flags & IPFUNCS_HOSTS_IP))
        return;

    if (dhcp_info_free_list)
    {
        info = dhcp_info_free_list;
        dhcp_info_free_list = info->next;
    }
    else
        info = (DHCPInfo*)snort_calloc(sizeof(DHCPInfo));

    if (asd.add_flow_data(info, APPID_SESSION_DATA_DHCP_INFO,
        (AppIdFreeFCN)BootpServiceDetector::AppIdFreeDhcpInfo))
    {
        BootpServiceDetector::AppIdFreeDhcpInfo(info);
        return;
    }
    asd.set_session_flags(APPID_SESSION_HAS_DHCP_INFO);
    info->ipAddr = ip;
    memcpy(info->eth_addr, mac, sizeof(info->eth_addr));
    info->subnetmask = subnetmask;
    info->leaseSecs = leaseSecs;
    info->router = router;
}

