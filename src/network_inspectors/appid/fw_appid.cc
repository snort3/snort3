//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// fw_appid.cc author Sourcefire Inc.

#include "fw_appid.h"

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/tcp.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

#include "appid_stats.h"
#include "app_forecast.h"
#include "app_info_table.h"

#include "host_port_app_cache.h"
#include "lua_detector_module.h"
#include "client_plugins/client_app_base.h"
#include "detector_plugins/detector_http.h"
#include "detector_plugins/detector_dns.h"
#include "service_plugins/service_base.h"
#include "service_plugins/service_ssl.h"
#include "service_plugins/service_util.h"
#include "util/common_util.h"
#include "util/ip_funcs.h"
#include "util/network_set.h"
#include "time/packet_time.h"
#include "sfip/sf_ip.h"
#include "stream/stream_api.h"

#if 1 // FIXIT-M hacks
struct HttpParsedHeaders
{
    struct HttpBuf
    {
        char* start;
        int len;
    };

    HttpBuf host;
    HttpBuf url;
    HttpBuf userAgent;
    HttpBuf referer;
    HttpBuf via;
    HttpBuf contentType;
    HttpBuf responseCode;
};

#define HTTP_XFF_FIELD_X_FORWARDED_FOR ""
#define HTTP_XFF_FIELD_TRUE_CLIENT_IP ""

#endif

#define MAX_ATTR_LEN           1024
#define HTTP_PREFIX "http://"

#define APP_MAPPING_FILE "appMapping.data"

#ifdef RNA_DEBUG_PE
static const char* MODULE_NAME = "fw_appid";
#endif

static volatile int app_id_debug_flag;
static FWDebugSessionConstraints app_id_debug_info;
char app_id_debug_session[FW_DEBUG_SESSION_ID_SIZE];
bool app_id_debug_session_flag;

ProfileStats tpPerfStats;
ProfileStats tpLibPerfStats;
ProfileStats httpPerfStats;
ProfileStats clientMatchPerfStats;
ProfileStats serviceMatchPerfStats;

#define HTTP_PATTERN_MAX_LEN    1024
#define PORT_MAX 65535

unsigned long app_id_raw_packet_count = 0;
unsigned long app_id_processed_packet_count = 0;
unsigned long app_id_ignored_packet_count = 0;
int app_id_debug;
static int ptype_scan_counts[NUMBER_OF_PTYPES];

static void ProcessThirdPartyResults(Packet* p, AppIdData* appIdSession, int confidence,
    AppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data);
static void ExamineRtmpMetadata(AppIdData* appIdSession);

void dump_appid_stats()
{
    LogMessage("Application Identification Preprocessor:\n");
    LogMessage("   Total packets received : %lu\n", app_id_raw_packet_count);
    LogMessage("  Total packets processed : %lu\n", app_id_processed_packet_count);
    if (thirdparty_appid_module)
        thirdparty_appid_module->print_stats();
    LogMessage("    Total packets ignored : %lu\n", app_id_ignored_packet_count);
    AppIdServiceStateDumpStats();
    RNAPndDumpLuaStats();
}

void reset_appid_stats(int, void*)
{
    app_id_raw_packet_count = 0;
    app_id_processed_packet_count = 0;
    app_id_ignored_packet_count = 0;
    if (thirdparty_appid_module)
        thirdparty_appid_module->reset_stats();
}


/* The UNSYNCED_SNORT_ID value is to cheaply insure we get
   the value from snort rather than assume */
#define UNSYNCED_SNORT_ID   0x5555

AppIdData* appSharedDataAlloc(IpProtocol proto, const sfip_t* ip)
{
    // FIXIT - should appid_flow_data_id be global to all threads?
    static THREAD_LOCAL uint32_t appid_flow_data_id = 0;
    AppIdData* data = new AppIdData;

    // should be freed by flow
    // if (app_id_free_list)
    // {
    //     data = app_id_free_list;
    //     app_id_free_list = data->next;
    //     data->reset();
    // }

    if (thirdparty_appid_module)
        if (!(data->tpsession = thirdparty_appid_module->session_create()))
            FatalError("Could not allocate AppIdData->tpsession data");

    data->id = ++appid_flow_data_id;
    data->common.fsf_type.flow_type = APPID_SESSION_TYPE_NORMAL;
    data->proto = proto;
    data->common.initiator_ip = *ip;
    data->snortId = UNSYNCED_SNORT_ID;
    data->search_support_type = SEARCH_SUPPORT_TYPE_UNKNOWN;
    return data;
}

static inline AppIdData* appSharedCreateData(const Packet* p, IpProtocol proto, int direction)
{
    AppIdData* data;
    const sfip_t* ip;

    ip = (direction == APP_ID_FROM_INITIATOR)
        ? p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
    data = appSharedDataAlloc(proto, ip);

    if ( ( proto == IpProtocol::TCP || proto == IpProtocol::UDP ) && ( p->ptrs.sp != p->ptrs.dp ) )
        data->common.initiator_port =
            (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;
    data->ssn = p->flow;
    data->stats.firstPktsecond = p->pkth->ts.tv_sec;

    p->flow->set_application_data(data);
    return data;
}

static inline void appSharedReInitData(AppIdData* session)
{
    session->miscAppId = APP_ID_NONE;

#ifdef REMOVED_WHILE_NOT_IN_USE
    //data
    if (isSslServiceAppId(session->tpAppId))
    {
        session->payloadAppId = session->referredPayloadAppId = session->tpPayloadAppId =
                    APP_ID_NONE;
        clearAppIdFlag(session, APPID_SESSION_CONTINUE);
        if (session->payloadVersion)
        {
            snort_free(session->payloadVersion);
            session->payloadVersion = nullptr;
        }
        if (session->hsession && session->hsession->url)
        {
            snort_free(session->hsession->url);
            session->hsession->url = nullptr;
        }
    }
#endif

    //service
    if (!getAppIdFlag(session, APPID_SESSION_STICKY_SERVICE))
    {
        clearAppIdFlag(session, APPID_SESSION_STICKY_SERVICE);

        session->tpAppId = session->serviceAppId = session->portServiceAppId = APP_ID_NONE;
        if (session->serviceVendor)
        {
            snort_free(session->serviceVendor);
            session->serviceVendor = nullptr;
        }
        if (session->serviceVersion)
        {
            snort_free(session->serviceVersion);
            session->serviceVersion = nullptr;
        }

        session->service_ip.clear();
        session->service_port = 0;
        session->rnaServiceState = RNA_STATE_NONE;
        session->serviceData = nullptr;
        AppIdFlowdataDeleteAllByMask(session, APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);
    }

    //client
    session->ClientAppId = session->ClientServiceAppId = APP_ID_NONE;
    if (session->clientVersion)
    {
        snort_free(session->clientVersion);
        session->clientVersion = nullptr;
    }
    session->rnaClientState = RNA_STATE_NONE;
    AppIdFlowdataDeleteAllByMask(session, APPID_SESSION_DATA_CLIENT_MODSTATE_BIT);

    //3rd party cleaning
    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(session->tpsession, 1);
    session->init_tpPackets = 0;
    session->resp_tpPackets = 0;

    session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
    clearAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED|APPID_SESSION_CLIENT_DETECTED|
        APPID_SESSION_SSL_SESSION|APPID_SESSION_HTTP_SESSION|APPID_SESSION_APP_REINSPECT);
}

void fwAppIdFini(AppIdConfig* pConfig)
{
#ifdef RNA_FULL_CLEANUP
    AppIdData* app_id;
    TmpAppIdData* tmp_app_id;

    while ((app_id = app_id_free_list))
    {
        app_id_free_list = app_id->next;
        snort_free(app_id);
    }

    while ((tmp_app_id = tmp_app_id_free_list))
    {
        tmp_app_id_free_list = tmp_app_id->next;
        snort_free(tmp_app_id);
    }
    AppIdFlowdataFini();
#endif

    appInfoTableFini(pConfig);
}

static inline int PENetworkMatch(const sfip_t* pktAddr, const PortExclusion* pe)
{
    const uint32_t* pkt = pktAddr->ip32;
    const uint32_t* nm = pe->netmask.u6_addr32;
    const uint32_t* peIP = pe->ip.u6_addr32;
    return (((pkt[0] & nm[0]) == peIP[0])
           && ((pkt[1] & nm[1]) == peIP[1])
           && ((pkt[2] & nm[2]) == peIP[2])
           && ((pkt[3] & nm[3]) == peIP[3]));
}

static inline int checkPortExclusion(const Packet* pkt, int reversed)
{
    SF_LIST** src_port_exclusions;
    SF_LIST** dst_port_exclusions;
    SF_LIST* pe_list;
    PortExclusion* pe;
    const sfip_t* s_ip;
    uint16_t port;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if ( pkt->is_tcp() )
    {
        src_port_exclusions = pConfig->tcp_port_exclusions_src;
        dst_port_exclusions = pConfig->tcp_port_exclusions_dst;
    }
    else if ( pkt->is_udp() )
    {
        src_port_exclusions = pConfig->udp_port_exclusions_src;
        dst_port_exclusions = pConfig->udp_port_exclusions_dst;
    }
    else
        return 0;

    /* check the source port */
    port = reversed ? pkt->ptrs.dp : pkt->ptrs.sp;
    if ( port && (pe_list=src_port_exclusions[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_dst() : pkt->ptrs.ip_api.get_src();

        SF_LNODE* node;

        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
            {
#ifdef RNA_DEBUG_PE
                char inetBuffer[INET6_ADDRSTRLEN];
                inetBuffer[0] = 0;
                sfip_ntop(s_ip, inetBuffer, sizeof(inetBuffer));
                SFDEBUG(MODULE_NAME, "excluding src port: %d",port);
                SFDEBUG(MODULE_NAME, "for addresses src: %s", inetBuffer);
#endif
                return 1;
            }
        }
    }

    /* check the dest port */
    port = reversed ? pkt->ptrs.sp : pkt->ptrs.dp;
    if ( port && (pe_list=dst_port_exclusions[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_src() : pkt->ptrs.ip_api.get_dst();

        SF_LNODE* node;
        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
            {
#ifdef RNA_DEBUG_PE
                char inetBuffer[INET6_ADDRSTRLEN];
                inetBuffer[0] = 0;
                sfip_ntop(s_ip, inetBuffer, sizeof(inetBuffer));
                SFDEBUG(MODULE_NAME, "excluding dst port: %d",port);
                SFDEBUG(MODULE_NAME, "for addresses dst: %s", inetBuffer);
#endif
                return 1;
            }
        }
    }

    return 0;
}

static inline bool fwAppIdDebugCheck(Flow* flow, AppIdData* session, volatile int debug_flag,
    FWDebugSessionConstraints* info, char* debug_session, int direction)
{
    if (debug_flag)
    {
        assert(flow);
        const FlowKey* key = flow->key;

        if (((info->protocol == PktType::NONE) || info->protocol == key->pkt_type) &&
            (((!info->sport || info->sport == key->port_l) &&
            (!info->sip_flag || memcmp(&info->sip, key->ip_l, sizeof(info->sip)) == 0) &&
            (!info->dport || info->dport == key->port_h) &&
            (!info->dip_flag || memcmp(&info->dip, key->ip_h, sizeof(info->dip)) == 0)) ||
            ((!info->sport || info->sport == key->port_h) &&
            (!info->sip_flag || memcmp(&info->sip, key->ip_h, sizeof(info->sip)) == 0) &&
            (!info->dport || info->dport == key->port_l) &&
            (!info->dip_flag || memcmp(&info->dip, key->ip_l, sizeof(info->dip)) == 0))))
        {
            int af;
            sfip_t sip;
            sfip_t dip;
            unsigned offset;
            uint16_t sport;
            uint16_t dport;
            char sipstr[INET6_ADDRSTRLEN];
            char dipstr[INET6_ADDRSTRLEN];

            if (session && session->common.fsf_type.flow_type != APPID_SESSION_TYPE_IGNORE)
            {
                if (session->common.initiator_port)
                {
                    if (session->common.initiator_port == key->port_l)
                    {
                        sfip_set_raw(&sip, key->ip_l, AF_INET);
                        sfip_set_raw(&dip, key->ip_l, AF_INET);
                        sport = key->port_l;
                        dport = key->port_h;
                    }
                    else
                    {
                        sfip_set_raw(&sip, key->ip_l, AF_INET);
                        sfip_set_raw(&dip, key->ip_l, AF_INET);
                        sport = key->port_h;
                        dport = key->port_l;
                    }
                }
                else
                {
                    // FIXIT-L: the key_ip var was added to be able to call sfip_fast_eq6, need to
                    // verify this works... not tested as yet...
                    sfip_t key_ip;
                    memcpy(key_ip.ip32, key->ip_l, sizeof(key_ip.ip32));
                    if (sfip_fast_eq6(&session->common.initiator_ip, &key_ip) == 0)
                    {
                        sfip_set_raw(&sip, key->ip_l, AF_INET);
                        sfip_set_raw(&dip, key->ip_h, AF_INET);
                        sport = key->port_l;
                        dport = key->port_h;
                    }
                    else
                    {
                        sfip_set_raw(&sip, key->ip_l, AF_INET);
                        sfip_set_raw(&dip, key->ip_h, AF_INET);
                        sport = key->port_h;
                        dport = key->port_l;
                    }
                }
            }
            else
            {
                sfip_set_raw(&sip, key->ip_l, AF_INET);
                sfip_set_raw(&dip, key->ip_h, AF_INET);
                sport = key->port_l;
                dport = key->port_h;
            }
            sipstr[0] = 0;
            if ( sip.ip32[0] || sip.ip32[1] || sip.ip16[4] ||
                (sip.ip16[5] && sip.ip16[5] != 0xffff) )
            {
                af = AF_INET6;
                offset = 0;
            }
            else
            {
                af = AF_INET;
                offset = 12;
            }

            inet_ntop(af, &sip.ip8[offset], sipstr, sizeof(sipstr));
            dipstr[0] = 0;
            if ( dip.ip32[0] || dip.ip32[1] || dip.ip16[4] ||
                (dip.ip16[5] && dip.ip16[5] != 0xFFFF) )
            {
                af = AF_INET6;
                offset = 0;
            }
            else
            {
                af = AF_INET;
                offset = 12;
            }

            inet_ntop(af, &dip.ip8[offset], dipstr, sizeof(dipstr));
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
            snprintf(debug_session, FW_DEBUG_SESSION_ID_SIZE, "%s-%u -> %s-%u %u%s AS %u I %u",
                sipstr, (unsigned)sport, dipstr, (unsigned)dport, (unsigned)key->pkt_type,
                (direction == APP_ID_FROM_INITIATOR) ? "" : " R",
                (unsigned)key->addressSpaceId, get_instance_id());
#else
            snprintf(debug_session, FW_DEBUG_SESSION_ID_SIZE, "%s-%u -> %s-%u %u%s I %u",
                sipstr, (unsigned)sport, dipstr, (unsigned)dport, (unsigned)key->pkt_type,
                (direction == APP_ID_FROM_INITIATOR) ? "" : " R", get_instance_id());
#endif
            return true;
        }
    }
    return false;
}

static inline void appIdDebugParse(const char* desc, const uint8_t* data, uint32_t length,
    volatile int* debug_flag, FWDebugSessionConstraints* info)
{
    *debug_flag = 0;
    memset(info, 0, sizeof(*info));
    do
    {
        if (length >= sizeof(info->protocol))
        {
            info->protocol = static_cast<PktType>(*data);
            length -= sizeof(info->protocol);
            data += sizeof(info->protocol);
        }
        else
            break;

        if (length >= sizeof(info->sip))
        {
            memcpy(&info->sip, data, sizeof(info->sip));
            if (info->sip.u6_addr32[1] || info->sip.u6_addr32[2] || info->sip.u6_addr32[3])
                info->sip_flag = 1;
            else if (info->sip.u6_addr32[0])
            {
                info->sip.u6_addr32[3] = info->sip.u6_addr32[0];
                info->sip.u6_addr32[0] = 0;
                info->sip.u6_addr16[5] = 0xFFFF;
                info->sip_flag = 1;
            }
            length -= sizeof(info->sip);
            data += sizeof(info->sip);
        }
        else
            break;

        if (length >= sizeof(info->sport))
        {
            memcpy(&info->sport, data, sizeof(info->sport));
            length -= sizeof(info->sport);
            data += sizeof(info->sport);
        }
        else
            break;

        if (length >= sizeof(info->dip))
        {
            memcpy(&info->dip, data, sizeof(info->dip));
            if (info->dip.u6_addr32[1] || info->dip.u6_addr32[2] || info->dip.u6_addr32[3])
                info->dip_flag = 1;
            else if (info->dip.u6_addr32[0])
            {
                info->dip.u6_addr32[3] = info->dip.u6_addr32[0];
                info->dip.u6_addr32[0] = 0;
                info->dip.u6_addr16[5] = 0xFFFF;
                info->dip_flag = 1;
            }
            length -= sizeof(info->dip);
            data += sizeof(info->dip);
        }
        else
            break;

        if (length >= sizeof(info->dport))
            memcpy(&info->dport, data, sizeof(info->dport));
        else
            break;
    }
    while (0);

    if (info->protocol != PktType::NONE || info->sip_flag || info->sport || info->dip_flag ||
        info->dport)
    {
        int saf;
        int daf;
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        if (!info->sip.u6_addr32[0] && !info->sip.u6_addr32[0] && !info->sip.u6_addr16[4] &&
            info->sip.u6_addr16[5] == 0xFFFF)
        {
            saf = AF_INET;
        }
        else
            saf = AF_INET6;
        if (!info->dip.u6_addr32[0] && !info->dip.u6_addr32[0] && !info->dip.u6_addr16[4] &&
            info->dip.u6_addr16[5] == 0xFFFF)
        {
            daf = AF_INET;
        }
        else
            daf = AF_INET6;
        if (!info->sip_flag)
            saf = daf;
        if (!info->dip_flag)
            daf = saf;
        sipstr[0] = 0;
        inet_ntop(saf, saf == AF_INET ? &info->sip.u6_addr32[3] : info->sip.u6_addr32, sipstr,
            sizeof(sipstr));
        dipstr[0] = 0;
        inet_ntop(daf, daf == AF_INET ? &info->dip.u6_addr32[3] : info->dip.u6_addr32, dipstr,
            sizeof(dipstr));
        LogMessage("Debugging %s with %s-%u and %s-%u %u\n", desc,
            sipstr, (unsigned)info->sport,
            dipstr, (unsigned)info->dport,
            (unsigned)info->protocol);
        *debug_flag = 1;
    }
    else
        LogMessage("Debugging %s disabled\n", desc);
}

int AppIdDebug(uint16_t, const uint8_t* const data, uint32_t length, void**, char*, int)
{
    appIdDebugParse("appId", data, length, &app_id_debug_flag, &app_id_debug_info);
    return 0;
}

unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone)
{
    NetworkSet* net_list;
    unsigned flags;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (zone >= 0 && zone < MAX_ZONES && pConfig->net_list_by_zone[zone])
        net_list = pConfig->net_list_by_zone[zone];
    else
        net_list = pConfig->net_list;

    NetworkSet_ContainsEx(net_list, ip4, &flags);
    return flags;
}

static inline unsigned isIPMonitored(const Packet* p, int dst)
{
    const sfip_t* sf_ip;
    NetworkSet* net_list;
    unsigned flags;
    int32_t zone;
    NSIPv6Addr ip6;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (!dst)
    {
        zone = p->pkth->ingress_group;
        sf_ip = p->ptrs.ip_api.get_src();
    }
    else
    {
        zone = (p->pkth->egress_index == DAQ_PKTHDR_UNKNOWN) ? p->pkth->ingress_group
            :
            p->pkth->egress_group;
        if (zone == DAQ_PKTHDR_FLOOD)
            return 0;
        sf_ip = p->ptrs.ip_api.get_dst();
    }

    if (zone >= 0 && zone < MAX_ZONES && pConfig->net_list_by_zone[zone])
        net_list = pConfig->net_list_by_zone[zone];
    else
        net_list = pConfig->net_list;

    if ( sf_ip->is_ip4() )
    {
        if (sf_ip->ip32[0] == 0xFFFFFFFF)
            return IPFUNCS_CHECKED;
        NetworkSet_ContainsEx(net_list, ntohl(sf_ip->ip32[0]), &flags);
    }
    else
    {
        memcpy(&ip6, sf_ip->ip32, sizeof(ip6));
        NSIPv6AddrNtoH(&ip6);
        NetworkSet_Contains6Ex(net_list, &ip6, &flags);
    }

    return flags | IPFUNCS_CHECKED;
}

static inline bool isSpecialSessionMonitored(const Packet* p)
{
    if ( p->is_ip4() )
    {
        if (p->is_udp() && ((p->ptrs.sp == 68 && p->ptrs.dp == 67)
            || (p->ptrs.sp == 67 &&  p->ptrs.dp == 68)))
        {
            return true;
        }
    }
    return false;
}

static inline uint64_t isSessionMonitored(const Packet* p, int dir, AppIdData* session)
{
    uint64_t flags;
//  FIXIT-M: Determine correct replacement for this _dpd call
#ifdef REMOVED_WHILE_NOT_IN_USE
    uint64_t flow_flags = _dpd.isAppIdRequired() ? APPID_SESSION_DISCOVER_APP : 0;
#else
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;
#endif

    flow_flags |= (dir == APP_ID_FROM_INITIATOR) ? APPID_SESSION_INITIATOR_SEEN :
        APPID_SESSION_RESPONDER_SEEN;
    if (session)
    {
        flow_flags |= session->common.flags;
        if (session->common.policyId != appIdPolicyId)
        {
            if (checkPortExclusion(p, dir == APP_ID_FROM_RESPONDER))
            {
                flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
                    APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
                flow_flags &= ~(APPID_SESSION_INITIATOR_MONITORED |
                    APPID_SESSION_RESPONDER_MONITORED);
                return flow_flags;
            }
            if (dir == APP_ID_FROM_INITIATOR)
            {
                if (getAppIdFlag(session, APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = isIPMonitored(p, 0);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }

                if (getAppIdFlag(session, APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = isIPMonitored(p, 1);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }
            }
            else
            {
                if (getAppIdFlag(session, APPID_SESSION_RESPONDER_CHECKED))
                {
                    flags = isIPMonitored(p, 0);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
                }

                if (getAppIdFlag(session, APPID_SESSION_INITIATOR_CHECKED))
                {
                    flags = isIPMonitored(p, 1);
                    if (flags & IPFUNCS_HOSTS_IP)
                        flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                    else
                        flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
                }
            }
        }

        if (getAppIdFlag(session, APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED)
            return flow_flags;

        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (!getAppIdFlag(session, APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = isIPMonitored(p, 0);
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;

                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP) && !getAppIdFlag(session,
                APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = isIPMonitored(p, 1);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
        else
        {
            if (!getAppIdFlag(session, APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = isIPMonitored(p, 0);
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
            if (!(flow_flags & APPID_SESSION_DISCOVER_APP) && !getAppIdFlag(session,
                APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = isIPMonitored(p, 1);
                if (flags & IPFUNCS_CHECKED)
                    flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                if (flags & IPFUNCS_USER_IP)
                    flow_flags |= APPID_SESSION_DISCOVER_USER;
                if (flags & IPFUNCS_APPLICATION)
                    flow_flags |= APPID_SESSION_DISCOVER_APP;
                if (isSpecialSessionMonitored(p))
                {
                    flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
                }
            }
        }
    }
    else if (checkPortExclusion(p, 0))
    {
        flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
            APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
    }
    else if (dir == APP_ID_FROM_INITIATOR)
    {
        flags = isIPMonitored(p, 0);
        flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
        if (flags & IPFUNCS_USER_IP)
            flow_flags |= APPID_SESSION_DISCOVER_USER;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = isIPMonitored(p, 1);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }
        if (isSpecialSessionMonitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }
    else
    {
        flags = isIPMonitored(p, 0);
        flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = isIPMonitored(p, 1);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }

        if (isSpecialSessionMonitored(p))
        {
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }

    return flow_flags;
}

static inline void seServiceAppIdData(AppIdData* session, AppId serviceAppId, char* vendor,
    char** version)
{
    if (serviceAppId <= APP_ID_NONE)
        return;

    //in drambuie, 3rd party is in INIT state after processing first GET requuest.
    if (serviceAppId == APP_ID_HTTP)
    {
        if (session->ClientServiceAppId == APP_ID_NONE)
        {
            session->ClientServiceAppId = serviceAppId;
        }
        return;
    }

    if (session->serviceAppId != serviceAppId)
    {
        session->serviceAppId = serviceAppId;

        if (pAppidActiveConfig->mod_config->instance_id)
            checkSandboxDetection(serviceAppId);

        /* Clear out previous values of vendor & version */
        if (session->serviceVendor)
        {
            snort_free(session->serviceVendor);
            session->serviceVendor = nullptr;
        }
        if (session->serviceVersion)
        {
            snort_free(session->serviceVersion);
            session->serviceVersion = nullptr;
        }

        if (vendor)
            session->serviceVendor = vendor;

        if (version && *version)
        {
            session->serviceVersion = *version;
            *version = nullptr;
        }
    }
    else
    {
        if (vendor || version)
        {
            /* Clear previous values */
            if (session->serviceVendor)
                snort_free(session->serviceVendor);
            if (session->serviceVersion)
                snort_free(session->serviceVersion);

            /* set vendor */
            if (vendor)
                session->serviceVendor = vendor;
            else
                session->serviceVendor = nullptr;

            /* set version */
            if (version && *version)
            {
                session->serviceVersion = *version;
                *version = nullptr;
            }
            else
                session->serviceVersion = nullptr;
        }
    }
}

static inline void setClientAppIdData(AppIdData* session, AppId ClientAppId, char** version)
{
    AppIdConfig* pConfig = pAppidActiveConfig;
    if (ClientAppId <= APP_ID_NONE || ClientAppId == APP_ID_HTTP)
        return;

    if (session->ClientAppId != ClientAppId)
    {
        unsigned prev_priority = appInfoEntryPriorityGet(session->ClientAppId, pConfig);
        unsigned curr_priority = appInfoEntryPriorityGet(ClientAppId, pConfig);

        if (pAppidActiveConfig->mod_config->instance_id)
            checkSandboxDetection(ClientAppId);

        if ((session->ClientAppId) && (prev_priority > curr_priority ))
            return;
        session->ClientAppId = ClientAppId;

        if (session->clientVersion)
            snort_free(session->clientVersion);

        if (version && *version)
        {
            session->clientVersion = *version;
            *version = nullptr;
        }
        else
            session->clientVersion = nullptr;
    }
    else if (version && *version)
    {
        if (session->clientVersion)
            snort_free(session->clientVersion);
        session->clientVersion = *version;
        *version = nullptr;
    }
}

static inline void setReferredPayloadAppIdData(AppIdData* session, AppId referredPayloadAppId)
{
    if (referredPayloadAppId <= APP_ID_NONE)
        return;

    if (session->referredPayloadAppId != referredPayloadAppId)
    {
        if (pAppidActiveConfig->mod_config->instance_id)
            checkSandboxDetection(referredPayloadAppId);

        session->referredPayloadAppId = referredPayloadAppId;
    }
}

static inline void setPayloadAppIdData(AppIdData* session, ApplicationId payloadAppId,
    char** version)
{
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (payloadAppId <= APP_ID_NONE)
        return;

    if (session->payloadAppId != payloadAppId)
    {
        unsigned prev_priority = appInfoEntryPriorityGet(session->payloadAppId, pConfig);
        unsigned curr_priority = appInfoEntryPriorityGet(payloadAppId, pConfig);

        if (pAppidActiveConfig->mod_config->instance_id)
            checkSandboxDetection(payloadAppId);

        if ((session->payloadAppId ) && (prev_priority > curr_priority ))
            return;

        session->payloadAppId = payloadAppId;

        if (session->payloadVersion)
            snort_free(session->payloadVersion);

        if (version && *version)
        {
            session->payloadVersion = *version;
            *version = nullptr;
        }
        else
            session->payloadVersion = nullptr;
    }
    else if (version && *version)
    {
        if (session->payloadVersion)
            snort_free(session->payloadVersion);
        session->payloadVersion = *version;
        *version = nullptr;
    }
}

static inline void clearSessionAppIdData(AppIdData* session)
{
    session->payloadAppId = APP_ID_UNKNOWN;
    session->serviceAppId = APP_ID_UNKNOWN;
    session->tpPayloadAppId = APP_ID_UNKNOWN;
    session->tpAppId = APP_ID_UNKNOWN;
    if (session->payloadVersion)
    {
        snort_free(session->payloadVersion);
        session->payloadVersion = nullptr;
    }
    if (session->serviceVendor)
    {
        snort_free(session->serviceVendor);
        session->serviceVendor = nullptr;
    }
    if (session->serviceVersion)
    {
        snort_free(session->serviceVersion);
        session->serviceVersion = nullptr;
    }

    if (session->tsession)
        session->appTlsSessionDataFree();

    if (session->hsession)
    	session->appHttpSessionDataFree();

    if (session->dsession)
    	session->appDNSSessionDataFree();

    if (thirdparty_appid_module)
        thirdparty_appid_module->session_delete(session->tpsession, 1);
}

static inline int initial_CHP_sweep(char** chp_buffers, MatchedCHPAction** ppmatches,
    AppIdData* session, const DetectorHttpConfig* pHttpConfig)
{
    CHPApp* cah = nullptr;
    int longest = 0;
    int size, i;
    httpSession* hsession;
    int scanKeyFoundSomething=0;
    CHPMatchTally* pTally = nullptr; // scanKeyCHP allocates a pointer, but we free it when ready

    hsession = session->hsession;

    for (i = 0; i <= MAX_KEY_PATTERN; i++)
    {
        ppmatches[i] = nullptr;
        if (chp_buffers[i] && (size = strlen(chp_buffers[i])) &&
            scanKeyCHP((PatternType)i, chp_buffers[i], size, &pTally, &ppmatches[i], pHttpConfig))
            scanKeyFoundSomething=1;
    }
    if (!scanKeyFoundSomething)
        return 0;

    for (i = 0; i < pTally->in_use_elements; i++)
    {
        // Only those items which have had their key_pattern_countdown field reduced to zero are a
        // full match
        if (pTally->item[i].key_pattern_countdown)
            continue;
        if (longest < pTally->item[i].key_pattern_length_sum)
        {
            // We've found a new longest pattern set
            longest = pTally->item[i].key_pattern_length_sum;
            cah = pTally->item[i].chpapp;
        }
    }
    // either we have a candidate or we don't so we can free the tally structure either way.
    free(pTally);

    if (cah == nullptr)
    {
        // We were planning to pass along the content of ppmatches to the second phase and let
        // them be freed inside scanCHP, but we have no candidate so we free here
        for (i = 0; i <= MAX_KEY_PATTERN; i++)
        {
            if (ppmatches[i])
            {
                FreeMatchedCHPActions(ppmatches[i]);
                ppmatches[i] = nullptr;
            }
        }
        return 0;
    }

    /***************************************************************
       candidate has been chosen and it is pointed to by cah
       we will preserve any match sets until the calls to scanCHP()
      ***************************************************************/
    for (i = 0; i < NUMBER_OF_PTYPES; i++)
    {
        ptype_scan_counts[i] = cah->ptype_scan_counts[i];
        hsession->ptype_req_counts[i] = cah->ptype_req_counts[i] +
            cah->ptype_rewrite_insert_used[i];
        if (i > 3 && !cah->ptype_scan_counts[i] && !getAppIdFlag(session,
            APPID_SESSION_SPDY_SESSION))
        {
            clearAppIdFlag(session, APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_clear(session->tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
    }
    hsession->chp_candidate = cah->appIdInstance;
    hsession->app_type_flags = cah->app_type_flags;
    hsession->num_matches = cah->num_matches;
    hsession->num_scans = cah->num_scans;

    if (thirdparty_appid_module)
    {
        if ((ptype_scan_counts[CONTENT_TYPE_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession,
                TP_ATTR_COPY_RESPONSE_CONTENT);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession,
                TP_ATTR_COPY_RESPONSE_CONTENT);

        if ((ptype_scan_counts[LOCATION_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession,
                TP_ATTR_COPY_RESPONSE_LOCATION);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession,
                TP_ATTR_COPY_RESPONSE_LOCATION);

        if ((ptype_scan_counts[BODY_PT]))
            thirdparty_appid_module->session_attr_set(session->tpsession,
                TP_ATTR_COPY_RESPONSE_BODY);
        else
            thirdparty_appid_module->session_attr_clear(session->tpsession,
                TP_ATTR_COPY_RESPONSE_BODY);
    }

    return 1;
}

static const char* httpFieldName[ NUMBER_OF_PTYPES ] = // for use in debug messages
{
    "useragent",
    "host",
    "referer",
    "uri",
    "cookie",
    "req_body",
    "content_type",
    "location",
    "body",
};

static inline void processCHP(AppIdData* session, char** version, Packet* p, const
    AppIdConfig* pConfig)
{
    int i, size;
    int found_in_buffer = 0;
    char* user = nullptr;
    AppId chp_final;
    AppId ret = 0;
    httpSession* http_session = session->hsession;

    char* chp_buffers[NUMBER_OF_PTYPES] =
    {
        http_session->useragent,
        http_session->host,
        http_session->referer,
        http_session->uri,
        http_session->cookie,
        http_session->req_body,
        http_session->content_type,
        http_session->location,
        http_session->body,
    };

    char* chp_rewritten[NUMBER_OF_PTYPES] =
    {
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr
    };

    MatchedCHPAction* chp_matches[NUMBER_OF_PTYPES] =
    {
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr,
        nullptr,nullptr,nullptr
    };

    if (http_session->chp_hold_flow)
        http_session->chp_finished = 0;

    if (!http_session->chp_candidate)
    {
        // remove artifacts from previous matches before we start again.
        for (i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if (http_session->new_field[i])
            {
                snort_free(http_session->new_field[i]);
                http_session->new_field[i] = nullptr;
            }
        }

        if (!initial_CHP_sweep(chp_buffers, chp_matches, session, &pConfig->detectorHttpConfig))
            http_session->chp_finished = 1; // this is a failure case.
    }
    if (!http_session->chp_finished && http_session->chp_candidate)
    {
        for (i = 0; i < NUMBER_OF_PTYPES; i++)
        {
            if (ptype_scan_counts[i] && chp_buffers[i] && (size = strlen(chp_buffers[i])) > 0)
            {
                found_in_buffer = 0;
                ret = scanCHP((PatternType)i, chp_buffers[i], size, chp_matches[i], version,
                    &user, &chp_rewritten[i], &found_in_buffer,
                    http_session, p, &pConfig->detectorHttpConfig);
                chp_matches[i] = nullptr; // freed by scanCHP()
                http_session->total_found += found_in_buffer;
                http_session->num_scans--;
                ptype_scan_counts[i] = 0;
                // Give up if scanCHP returns nothing, OR
                // (if we did not match the right numbher of patterns in this field AND EITHER
                // (there is no match quota [all must match]) OR
                // (the total number of matches is less than our match quota))
                if (!ret ||
                    (found_in_buffer < http_session->ptype_req_counts[i] &&
                    (!http_session->num_matches ||
                    http_session->total_found < http_session->num_matches)))
                {
                    http_session->chp_candidate = 0;
                    break;
                }
                /* We are finished if we have a num_matches target and we've met it or
                   if we have done all the scans */
                if (!http_session->num_scans ||
                    (http_session->num_matches && http_session->total_found >=
                    http_session->num_matches))
                {
                    http_session->chp_finished = 1;
                    break;
                }
            }
            else if (ptype_scan_counts[i] && !http_session->chp_hold_flow)
            {
                /* we have a scan count, but nothing in the buffer, so we should drop out of CHP */
                http_session->chp_candidate = 0;
                break;
            }
        }
        if (!http_session->chp_candidate)
        {
            http_session->chp_finished = 1;
            if (*version)
            {
                snort_free(*version);
                *version = nullptr;
            }
            if (user)
            {
                snort_free(user);
                user = nullptr;
            }
            for (i = 0; i < NUMBER_OF_PTYPES; i++)
            {
                if (nullptr != chp_rewritten[i])
                {
                    snort_free(chp_rewritten[i]);
                    chp_rewritten[i] = nullptr;
                }
            }
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));

            // Make it possible for other detectors to run.
            http_session->skip_simple_detect = false;
            return;
        }
        if (http_session->chp_candidate && http_session->chp_finished)
        {
            chp_final = http_session->chp_alt_candidate ?
                http_session->chp_alt_candidate :
                http_session->chp_candidate >> CHP_APPID_BITS_FOR_INSTANCE; // transform the
                                                                            // instance into the
                                                                            // appId.
            if (http_session->app_type_flags & APP_TYPE_SERVICE)
            {
                seServiceAppIdData(session, chp_final, nullptr, version);
            }

            if (http_session->app_type_flags & APP_TYPE_CLIENT)
            {
                setClientAppIdData(session, chp_final, version);
            }

            if (http_session->app_type_flags & APP_TYPE_PAYLOAD)
            {
                setPayloadAppIdData(session, (ApplicationId)chp_final, version);
            }

            if (http_session->fflow && http_session->fflow->flow_prepared)
            {
                finalizeFflow(http_session->fflow, http_session->app_type_flags,
                    (http_session->fflow->appId ? http_session->fflow->appId : chp_final), p);
                snort_free(http_session->fflow);
                http_session->fflow = nullptr;
            }
            if (*version)
                *version = nullptr;
            if (user)
            {
                session->username = user;
                user = nullptr;
                if (http_session->app_type_flags & APP_TYPE_SERVICE)
                    session->usernameService = chp_final;
                else
                    session->usernameService = session->serviceAppId;
                setAppIdFlag(session, APPID_SESSION_LOGIN_SUCCEEDED);
            }
            for (i = 0; i < NUMBER_OF_PTYPES; i++)
            {
                if (nullptr != chp_rewritten[i])
                {
                    if (app_id_debug_session_flag)
                        LogMessage("AppIdDbg %s rewritten %s: %s\n", app_id_debug_session,
                            httpFieldName[i], chp_rewritten[i]);
                    if (http_session->new_field[i])
                        snort_free(http_session->new_field[i]);
                    http_session->new_field[i] = chp_rewritten[i];
                    chp_rewritten[i] = nullptr;
                }
            }
            http_session->chp_candidate = 0;
            //if we're doing safesearch rewrites, we want to continue to hold the flow
            if (!http_session->get_offsets_from_rebuilt)
                http_session->chp_hold_flow = 0;
            session->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            session->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));
        }
        else /* if we have a candidate, but we're not finished */
        {
            if (user)
            {
                snort_free(user);
                user = nullptr;
            }
            for (i = 0; i < NUMBER_OF_PTYPES; i++)
            {
                if (nullptr != chp_rewritten[i])
                {
                    snort_free(chp_rewritten[i]);
                    chp_rewritten[i] = nullptr;
                }
            }
        }
    }
}

static inline bool payloadAppIdIsSet(AppIdData* session)
{
    return ( session->payloadAppId || session->tpPayloadAppId );
}

static inline void clearMiscHttpFlags(AppIdData* session)
{
    if (!getAppIdFlag(session, APPID_SESSION_SPDY_SESSION))
    {
        clearAppIdFlag(session, APPID_SESSION_CHP_INSPECTING);
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_attr_clear(session->tpsession,
                TP_ATTR_CONTINUE_MONITORING);
    }
}

static inline int processHTTPPacket(Packet* p, AppIdData* session, int direction,
    HttpParsedHeaders* const, const AppIdConfig* pConfig)
{
    Profile http_profile_context(httpPerfStats);
    constexpr auto RESPONSE_CODE_LENGTH = 3;
    HeaderMatchedPatterns hmp;
    httpSession* http_session;
    int start, end, size;
    char* version = nullptr;
    char* vendorVersion = nullptr;
    char* vendor = nullptr;
    AppId serviceAppId = 0;
    AppId ClientAppId = 0;
    AppId payloadAppId = 0;
    AppId referredPayloadAppId = 0;
    char* host;
    char* url;
    char* useragent;
    char* referer;
    char* via;
    AppInfoTableEntry* entry;

    http_session = session->hsession;
    if (!http_session)
    {
        clearSessionAppIdData(session);
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s attempt to process HTTP packet with no HTTP data\n",
                app_id_debug_session);

        return 0;
    }

    // For fragmented HTTP headers, do not process if none of the fields are set.
    // These fields will get set when the HTTP header is reassembled.
    if ((!http_session->useragent) && (!http_session->host) && (!http_session->referer) &&
        (!http_session->uri))
    {
        if (!http_session->skip_simple_detect)
            clearMiscHttpFlags(session);

        return 0;
    }

    if (direction == APP_ID_FROM_RESPONDER && !getAppIdFlag(session,
        APPID_SESSION_RESPONSE_CODE_CHECKED))
    {
        if (http_session->response_code)
        {
            setAppIdFlag(session, APPID_SESSION_RESPONSE_CODE_CHECKED);
            if (strlen(http_session->response_code) != RESPONSE_CODE_LENGTH)
            {
                /* received bad response code. Stop processing this session */
                clearSessionAppIdData(session);
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s bad http response code\n", app_id_debug_session);

                return 0;
            }
        }
#if RESPONSE_CODE_PACKET_THRESHHOLD
        else if (++(http_session->response_code_packets) == RESPONSE_CODE_PACKET_THRESHHOLD)
        {
            setAppIdFlag(session, APPID_SESSION_RESPONSE_CODE_CHECKED);
            /* didn't receive response code in first X packets. Stop processing this session */
            clearSessionAppIdData(session);
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s no response code received\n", app_id_debug_session);
            PREPROC_PROFILE_END(httpPerfStats);
            return 0;
        }
#endif
    }
    host = http_session->host;
    url = http_session->url;
    via = http_session->via;
    useragent = http_session->useragent;
    referer = http_session->referer;
    memset(&hmp, 0, sizeof(hmp));

    if (session->serviceAppId == APP_ID_NONE)
    {
        session->serviceAppId = APP_ID_HTTP;
        if (pAppidActiveConfig->mod_config->instance_id)
            checkSandboxDetection(APP_ID_HTTP);
    }

    if (app_id_debug_session_flag)
        LogMessage("AppIdDbg %s chp_finished %d chp_hold_flow %d\n", app_id_debug_session,
            http_session->chp_finished, http_session->chp_hold_flow);

    if (!http_session->chp_finished || http_session->chp_hold_flow)
        processCHP(session, &version, p, pConfig);

    if (!http_session->skip_simple_detect)  // false unless a match happened with a call to
                                            // processCHP().
    {
        if (!getAppIdFlag(session, APPID_SESSION_APP_REINSPECT))
        {
            // Scan Server Header for Vendor & Version
            if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_VENDOR_FLAG) &&
                session->hsession->server) ||
                (!thirdparty_appid_module && getHTTPHeaderLocation(p->data, p->dsize,
                HTTP_ID_SERVER, &start, &end, &hmp, &pConfig->detectorHttpConfig) == 1))
            {
                if (session->serviceAppId == APP_ID_NONE || session->serviceAppId == APP_ID_HTTP)
                {
                    RNAServiceSubtype* subtype = nullptr;
                    RNAServiceSubtype** tmpSubtype;

                    if (thirdparty_appid_module)
                        getServerVendorVersion((uint8_t*)session->hsession->server, strlen(
                            session->hsession->server), &vendorVersion, &vendor, &subtype);
                    else
                        getServerVendorVersion(p->data + start, end - start, &vendorVersion,
                            &vendor, &subtype);
                    if (vendor || vendorVersion)
                    {
                        if (session->serviceVendor)
                        {
                            snort_free(session->serviceVendor);
                            session->serviceVendor = nullptr;
                        }
                        if (session->serviceVersion)
                        {
                            snort_free(session->serviceVersion);
                            session->serviceVersion = nullptr;
                        }
                        if (vendor)
                            session->serviceVendor = vendor;
                        if (vendorVersion)
                            session->serviceVersion = vendorVersion;
                        session->scan_flags &= ~SCAN_HTTP_VENDOR_FLAG;
                    }
                    if (subtype)
                    {
                        for (tmpSubtype = &session->subtype; *tmpSubtype; tmpSubtype =
                            &(*tmpSubtype)->next)
                            ;

                        *tmpSubtype = subtype;
                    }
                }
            }

            if (webdav_found(&hmp))
            {
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE &&
                    session->payloadAppId != payloadAppId)
                    LogMessage("AppIdDbg %s data is webdav\n", app_id_debug_session);
                setPayloadAppIdData(session, APP_ID_WEBDAV, nullptr);
            }

            // Scan User-Agent for Browser types or Skype
            if ((session->scan_flags & SCAN_HTTP_USER_AGENT_FLAG) && session->ClientAppId <=
                APP_ID_NONE && useragent && (size = strlen(useragent)) > 0)
            {
                if (version)
                {
                    snort_free(version);
                    version = nullptr;
                }
                identifyUserAgent((uint8_t*)useragent, size, &serviceAppId, &ClientAppId, &version,
                    &pConfig->detectorHttpConfig);
                if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId !=
                    APP_ID_HTTP && session->serviceAppId != serviceAppId)
                    LogMessage("AppIdDbg %s User Agent is service %d\n", app_id_debug_session,
                        serviceAppId);
                seServiceAppIdData(session, serviceAppId, nullptr, nullptr);
                if (app_id_debug_session_flag && ClientAppId > APP_ID_NONE && ClientAppId !=
                    APP_ID_HTTP && session->ClientAppId != ClientAppId)
                    LogMessage("AppIdDbg %s User Agent is client %d\n", app_id_debug_session,
                        ClientAppId);
                setClientAppIdData(session, ClientAppId, &version);
                session->scan_flags &= ~SCAN_HTTP_USER_AGENT_FLAG;
            }

            /* Scan Via Header for squid */
            if (!payloadAppIdIsSet(session) && (session->scan_flags & SCAN_HTTP_VIA_FLAG) && via &&
                (size = strlen(via)) > 0)
            {
                if (version)
                {
                    snort_free(version);
                    version = nullptr;
                }
                payloadAppId = geAppidByViaPattern((uint8_t*)via, size, &version,
                    &pConfig->detectorHttpConfig);
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE &&
                    session->payloadAppId != payloadAppId)
                    LogMessage("AppIdDbg %s VIA is data %d\n", app_id_debug_session,
                        payloadAppId);
                setPayloadAppIdData(session, (ApplicationId)payloadAppId, nullptr);
                session->scan_flags &= ~SCAN_HTTP_VIA_FLAG;
            }
        }

        /* Scan X-Working-With HTTP header */
        if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_XWORKINGWITH_FLAG) &&
            session->hsession->x_working_with) ||
            (!thirdparty_appid_module && getHTTPHeaderLocation(p->data, p->dsize,
            HTTP_ID_X_WORKING_WITH, &start, &end, &hmp, &pConfig->detectorHttpConfig) == 1))
        {
            AppId appId;

            if (thirdparty_appid_module)
                appId = scan_header_x_working_with((uint8_t*)session->hsession->x_working_with,
                    strlen(session->hsession->x_working_with), &version);
            else
                appId = scan_header_x_working_with(p->data + start, end - start, &version);

            if (appId)
            {
                if (direction == APP_ID_FROM_INITIATOR)
                {
                    if (app_id_debug_session_flag && ClientAppId > APP_ID_NONE && ClientAppId !=
                        APP_ID_HTTP && session->ClientAppId != ClientAppId)
                        LogMessage("AppIdDbg %s X is client %d\n", app_id_debug_session, appId);
                    setClientAppIdData(session, appId, &version);
                }
                else
                {
                    if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId !=
                        APP_ID_HTTP && session->serviceAppId != serviceAppId)
                        LogMessage("AppIdDbg %s X is service %d\n", app_id_debug_session, appId);
                    seServiceAppIdData(session, appId, nullptr, &version);
                }
                session->scan_flags &= ~SCAN_HTTP_XWORKINGWITH_FLAG;
            }
        }

        // Scan Content-Type Header for multimedia types and scan contents
        if ((thirdparty_appid_module && (session->scan_flags & SCAN_HTTP_CONTENT_TYPE_FLAG)
            && session->hsession->content_type  && !payloadAppIdIsSet(session)) ||
            (!thirdparty_appid_module && !payloadAppIdIsSet(session) &&
            getHTTPHeaderLocation(p->data, p->dsize, HTTP_ID_CONTENT_TYPE, &start, &end,
            &hmp, &pConfig->detectorHttpConfig) == 1))
        {
            if (thirdparty_appid_module)
                payloadAppId = geAppidByContentType((uint8_t*)session->hsession->content_type,
                    strlen(session->hsession->content_type), &pConfig->detectorHttpConfig);
            else
                payloadAppId = geAppidByContentType(p->data + start, end - start,
                    &pConfig->detectorHttpConfig);
            if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE && session->payloadAppId !=
                payloadAppId)
                LogMessage("AppIdDbg %s Content-Type is data %d\n", app_id_debug_session,
                    payloadAppId);
            setPayloadAppIdData(session, (ApplicationId)payloadAppId, nullptr);
            session->scan_flags &= ~SCAN_HTTP_CONTENT_TYPE_FLAG;
        }

        if (session->scan_flags & SCAN_HTTP_HOST_URL_FLAG)
        {
            if (version)
            {
                snort_free(version);
                version = nullptr;
            }
            if (getAppIdFromUrl(host, url, &version, referer, &ClientAppId, &serviceAppId,
                &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig) == 1)
            {
                // do not overwrite a previously-set client or service
                if (session->ClientAppId <= APP_ID_NONE)
                {
                    if (app_id_debug_session_flag && ClientAppId > APP_ID_NONE && ClientAppId !=
                        APP_ID_HTTP && session->ClientAppId != ClientAppId)
                        LogMessage("AppIdDbg %s URL is client %d\n", app_id_debug_session,
                            ClientAppId);
                    setClientAppIdData(session, ClientAppId, nullptr);
                }
                if (session->serviceAppId <= APP_ID_NONE)
                {
                    if (app_id_debug_session_flag && serviceAppId > APP_ID_NONE && serviceAppId !=
                        APP_ID_HTTP && session->serviceAppId != serviceAppId)
                        LogMessage("AppIdDbg %s URL is service %d\n", app_id_debug_session,
                            serviceAppId);
                    seServiceAppIdData(session, serviceAppId, nullptr, nullptr);
                }
                // DO overwrite a previously-set data
                if (app_id_debug_session_flag && payloadAppId > APP_ID_NONE &&
                    session->payloadAppId != payloadAppId)
                    LogMessage("AppIdDbg %s URL is data %d\n", app_id_debug_session,
                        payloadAppId);
                setPayloadAppIdData(session, (ApplicationId)payloadAppId, &version);
                setReferredPayloadAppIdData(session, referredPayloadAppId);
            }
            session->scan_flags &= ~SCAN_HTTP_HOST_URL_FLAG;
        }

        if (session->ClientAppId == APP_ID_APPLE_CORE_MEDIA)
        {
            if (session->tpPayloadAppId > APP_ID_NONE)
            {
                entry = appInfoEntryGet(session->tpPayloadAppId, pConfig);
                // only move tpPayloadAppId to client if its got a ClientAppId
                if (entry->clientId > APP_ID_NONE)
                {
                    session->miscAppId = session->ClientAppId;
                    session->ClientAppId = session->tpPayloadAppId;
                }
            }
            else if (session->payloadAppId > APP_ID_NONE)
            {
                entry =  appInfoEntryGet(session->payloadAppId, pConfig);
                // only move payloadAppId to client if it has a ClientAppid
                if (entry->clientId > APP_ID_NONE)
                {
                    session->miscAppId = session->ClientAppId;
                    session->ClientAppId = session->payloadAppId;
                }
            }
        }

        clearMiscHttpFlags(session);
    }  // end DON'T skip_simple_detect

    return 0;
}

static inline void stopRnaServiceInspection(Packet* p, AppIdData* session, int direction)
{
    if (direction == APP_ID_FROM_INITIATOR)
    {
        session->service_ip = *p->ptrs.ip_api.get_dst();
        session->service_port = p->ptrs.dp;
    }
    else
    {
        session->service_ip = *p->ptrs.ip_api.get_src();
        session->service_port = p->ptrs.sp;
    }

    session->rnaServiceState = RNA_STATE_FINISHED;
    setAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED);
    clearAppIdFlag(session, APPID_SESSION_CONTINUE);
}

static inline bool isSslDecryptionEnabled(AppIdData* session)
{
    if (getAppIdFlag(session, APPID_SESSION_DECRYPTED))
        return 1;
// FIXIT-M J bad bad bad
// #ifdef UNIT_TEST
//     if (session->session_packet_count >= 12)
//         return 1;
//     return 0;
// #else
    return session->ssn->is_proxied();
// #endif
}

static inline void checkRestartAppDetection(AppIdData* session)
{
    if (getAppIdFlag(session, APPID_SESSION_DECRYPTED))
        return;
    if (!isSslDecryptionEnabled(session))
        return;

    AppId serviceAppId = pickServiceAppId(session);
#ifdef REMOVED_WHILE_NOT_IN_USE
    isSslServiceAppId(serviceAppId);
#else
    bool isSsl = false;
#endif

    // A session could either:
    // 1. Start of as SSL - captured with isSsl flag, OR
    // 2. It could start of as a non-SSL session and later change to SSL. For example, FTP->FTPS.
    //    In this case APPID_SESSION_ENCRYPTED flag is set by the protocol state machine.
    if (getAppIdFlag(session, APPID_SESSION_ENCRYPTED) || isSsl)
    {
        setAppIdFlag(session, APPID_SESSION_DECRYPTED);
        session->encrypted.serviceAppId = serviceAppId;
        session->encrypted.payloadAppId = pickPayloadId(session);
        session->encrypted.ClientAppId = pickClientAppId(session);
        session->encrypted.miscAppId = pickMiscAppId(session);
        session->encrypted.referredAppId = pickReferredPayloadId(session);
        appSharedReInitData(session);
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s SSL decryption is available, restarting app Detection\n",
                app_id_debug_session);

        // APPID_SESSION_ENCRYPTED is set upon receiving a command which upgrades the session to
        // SSL.
        // Next packet after the command will have encrypted traffic.
        // In the case of a session which starts as SSL, current packet itself is encrypted. Set
        // the special flag
        // APPID_SESSION_APP_REINSPECT_SSL which allows reinspection of this pcaket.
        if (isSsl)
            setAppIdFlag(session, APPID_SESSION_APP_REINSPECT_SSL);
    }
}

static inline void updateEncryptedAppId(AppIdData* session, AppId serviceAppId)
{
    switch (serviceAppId)
    {
    case APP_ID_HTTP:
        if (session->miscAppId == APP_ID_NSIIOPS || session->miscAppId == APP_ID_DDM_SSL
            || session->miscAppId == APP_ID_MSFT_GC_SSL || session->miscAppId ==
            APP_ID_SF_APPLIANCE_MGMT)
        {
            break;
        }
        session->miscAppId = APP_ID_HTTPS;
        break;
    case APP_ID_SMTP:
        session->miscAppId = APP_ID_SMTPS;
        break;
    case APP_ID_NNTP:
        session->miscAppId = APP_ID_NNTPS;
        break;
    case APP_ID_IMAP:
        session->miscAppId = APP_ID_IMAPS;
        break;
    case APP_ID_SHELL:
        session->miscAppId = APP_ID_SSHELL;
        break;
    case APP_ID_LDAP:
        session->miscAppId = APP_ID_LDAPS;
        break;
    case APP_ID_FTP_DATA:
        session->miscAppId = APP_ID_FTPSDATA;
        break;
    case APP_ID_FTP:
        session->miscAppId = APP_ID_FTPS;
        break;
    case APP_ID_TELNET:
        session->miscAppId = APP_ID_TELNET;
        break;
    case APP_ID_IRC:
        session->miscAppId = APP_ID_IRCS;
        break;
    case APP_ID_POP3:
        session->miscAppId = APP_ID_POP3S;
        break;
    default:
        break;
    }
}

// FIXIT - H Refactor to get this to work with SSL in snort++ environment
//static inline void ExamineSslMetadata(Packet* p, AppIdData* session, AppIdConfig* pConfig)
static inline void ExamineSslMetadata(Packet*, AppIdData*, AppIdConfig*)
{
#ifdef REMOVED_WHILE_NOT_IN_USE
    size_t size;
    int ret;
    AppId ClientAppId = 0;
    AppId payloadAppId = 0;

    if ((session->scan_flags & SCAN_SSL_HOST_FLAG) && session->tsession->tls_host)
    {
        size = strlen(session->tsession->tls_host);
        if ((ret = ssl_scan_hostname((const u_int8_t*)session->tsession->tls_host, size,
                &ClientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, ClientAppId, nullptr);
            setPayloadAppIdData(session, (ApplicationId)payloadAppId, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : ClientAppId));
        }
        session->scan_flags &= ~SCAN_SSL_HOST_FLAG;
        // ret = 0;
    }
    if (session->tsession->tls_cname)
    {
        size = strlen(session->tsession->tls_cname);
        if ((ret = ssl_scan_cname((const u_int8_t*)session->tsession->tls_cname, size,
                &ClientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, ClientAppId, nullptr);
            setPayloadAppIdData(session, (ApplicationId)payloadAppId, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : ClientAppId));
        }
        snort_free(session->tsession->tls_cname);
        session->tsession->tls_cname = nullptr;
        // ret = 0;
    }
    if (session->tsession->tls_orgUnit)
    {
        size = strlen(session->tsession->tls_orgUnit);
        if ((ret = ssl_scan_cname((const u_int8_t*)session->tsession->tls_orgUnit, size,
                &ClientAppId, &payloadAppId, &pConfig->serviceSslConfig)))
        {
            setClientAppIdData(session, ClientAppId, nullptr);
            setPayloadAppIdData(session, (ApplicationId)payloadAppId, nullptr);
            setSSLSquelch(p, ret, (ret == 1 ? payloadAppId : ClientAppId));
        }
        snort_free(session->tsession->tls_orgUnit);
        session->tsession->tls_orgUnit = nullptr;
        // ret = 0;
    }
#endif
}

static inline int RunClientDetectors(AppIdData* session,
    Packet* p,
    int direction,
    AppIdConfig* pConfig)
{
    int ret = CLIENT_APP_INPROCESS;

    if (session->clientData != nullptr)
    {
        ret = session->clientData->validate(p->data, p->dsize, direction,
            session, p, session->clientData->userData, pConfig);
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s %s client detector returned %d\n", app_id_debug_session,
                session->clientData->name ? session->clientData->name : "UNKNOWN", ret);
    }
    else if (    (session->candidate_client_list != nullptr)
        && (sflist_count(session->candidate_client_list) > 0) )
    {
        SF_LNODE* node;
        RNAClientAppModule* client;

        ret = CLIENT_APP_INPROCESS;
        (void)sflist_first(session->candidate_client_list, &node);
        while (node != nullptr)
        {
            int result;
            SF_LNODE* node_tmp;

            client = (RNAClientAppModule*)node->ndata;
            result = client->validate(p->data, p->dsize, direction,
                session, p, client->userData, pConfig);
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s %s client detector returned %d\n", app_id_debug_session,
                    client->name ? client->name : "UNKNOWN", result);

            node_tmp = node;
            sflist_next(&node);
            if (result == CLIENT_APP_SUCCESS)
            {
                ret = CLIENT_APP_SUCCESS;
                session->clientData = client;
                sflist_free(session->candidate_client_list);
                session->candidate_client_list = nullptr;
                break;    /* done */
            }
            else if (result != CLIENT_APP_INPROCESS)    /* fail */
            {
                sflist_remove_node(session->candidate_client_list, node_tmp);
            }
        }
    }

    return ret;
}

static inline void getOffsetsFromRebuilt(Packet* pkt, httpSession* hsession)
{
// size of "GET /\r\n\r\n"
#define MIN_HTTP_REQ_HEADER_SIZE 9
    const uint8_t cookieStr[] = "Cookie: ";
    unsigned cookieStrLen = sizeof(cookieStr)-1;
    const uint8_t crlf[] = "\r\n";
    unsigned crlfLen = sizeof(crlf)-1;
    const uint8_t crlfcrlf[] = "\r\n\r\n";
    unsigned crlfcrlfLen = sizeof(crlfcrlf)-1;
    const uint8_t* p;
    uint8_t* headerEnd;
    uint16_t headerSize;

    if (!pkt || !pkt->data || pkt->dsize < MIN_HTTP_REQ_HEADER_SIZE)
        return;

    p = pkt->data;

    if (!(headerEnd = (uint8_t*)service_strstr(p, pkt->dsize, crlfcrlf, crlfcrlfLen)))
        return;

    headerEnd += crlfcrlfLen;

    headerSize = headerEnd - p;

    //uri offset is the index of the first char after the first space in the data
    if (!(p = (uint8_t*)memchr(pkt->data, ' ', headerSize)))
        return;
    hsession->uriOffset = ++p - pkt->data;
    headerSize = headerEnd - p;

    //uri end offset is the index of the first CRLF sequence after uri offset
    if (!(p = (uint8_t*)service_strstr(p, headerSize, crlf, crlfLen)))
    {
        // clear uri offset if we can't find an end offset
        hsession->uriOffset = 0;
        return;
    }
    hsession->uriEndOffset = p - pkt->data;
    headerSize = headerEnd - p;

    //cookie offset is the index of the first char after the cookie header, "Cookie: "
    if (!(p = (uint8_t*)service_strstr(p, headerSize, cookieStr, cookieStrLen)))
        return;
    hsession->cookieOffset = p + cookieStrLen - pkt->data;
    headerSize = headerEnd - p;

    //cookie end offset is the index of the first CRLF sequence after cookie offset
    if (!(p = (uint8_t*)service_strstr(p, headerSize, crlf, crlfLen)))
    {
        // clear cookie offset if we can't find a cookie end offset
        hsession->cookieOffset = 0;
        return;
    }
    hsession->cookieEndOffset = p - pkt->data;
}

static int16_t snortId_for_ftp;
static int16_t snortId_for_ftp_data;
static int16_t snortId_for_imap;
static int16_t snortId_for_pop3;
static int16_t snortId_for_smtp;
static int16_t snortId_for_http2;

static inline void synchAppIdWithSnortId(AppId newAppId, Packet* p, AppIdData* session,
    AppIdConfig* pConfig)
{
    AppInfoTableEntry* entry;
    int16_t tempSnortId = session->snortId;

    if (tempSnortId == UNSYNCED_SNORT_ID)
    {
        tempSnortId = session->snortId = p->flow->ssn_state.application_protocol;
    }

    if (tempSnortId == snortId_for_ftp || tempSnortId == snortId_for_ftp_data ||
        tempSnortId == snortId_for_imap || tempSnortId == snortId_for_pop3 ||
        tempSnortId == snortId_for_smtp || tempSnortId == snortId_for_http2)
    {
        return; // These preprocessors, in snort proper, already know and expect these to remain
                // unchanged.
    }
    if ((entry = appInfoEntryGet(newAppId, pConfig)) && (tempSnortId = entry->snortId))
    {
        // Snort has a separate protocol ID for HTTP/2.  We don't.  So, when we
        // talk to them about it, we have to play by their rules.
        if ((newAppId == APP_ID_HTTP) && (session->is_http2))
            tempSnortId = snortId_for_http2;

        if (tempSnortId != session->snortId)
        {
            if (app_id_debug_session_flag)
                if (tempSnortId == snortId_for_http2)
                    LogMessage("AppIdDbg %s Telling Snort that it's HTTP/2\n",
                        app_id_debug_session);

            p->flow->ssn_state.application_protocol = tempSnortId;
            session->snortId = tempSnortId;
        }
    }
}

static inline void checkTerminateTpModule(uint16_t tpPktCount, AppIdData* session)
{
    if ((tpPktCount >= pAppidActiveConfig->mod_config->max_tp_flow_depth) ||
        (getAppIdFlag(session, APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) ==
        (APPID_SESSION_HTTP_SESSION | APPID_SESSION_APP_REINSPECT) &&
        session->hsession && session->hsession->uri &&
        (!session->hsession->chp_candidate || session->hsession->chp_finished)))
    {
        if (session->tpAppId == APP_ID_NONE)
            session->tpAppId = APP_ID_UNKNOWN;
        if (session->payloadAppId == APP_ID_NONE)
            session->payloadAppId = APP_ID_UNKNOWN;
        if (thirdparty_appid_module)
            thirdparty_appid_module->session_delete(session->tpsession, 1);
    }
}

//#define DEBUG_PACKETS
#ifdef DEBUG_PACKETS
#define printSnortPacket(SFSnortPacket_ptr) debug_printSnortPacket(SFSnortPacket_ptr)

#define CHAR_DUMP_WIDTH 60
static inline void debug_printSnortPacket(SFSnortPacket* p)
{
    if (app_id_debug_flag)
    {
        char* tweakedPayload;
        char* hexPayload;
        LogMessage("AppIdDbg \n");
        LogMessage("AppIdDbg ------------------------------------------------\n");
        LogMessage("AppIdDbg \n");
        if (p->data != nullptr && p->dsize)
        {
            tweakedPayload= (char*)snort_calloc((CHAR_DUMP_WIDTH*2)+1);  // room for hex
            if (tweakedPayload)
            {
                int j;
                int i;
                LogMessage("AppIdDbg data: (%d chars per line)\n",CHAR_DUMP_WIDTH);
                for (j=0; j<p->dsize; j+=CHAR_DUMP_WIDTH)
                {
                    for (i=j; i<p->dsize && i<(j+CHAR_DUMP_WIDTH); i++)
                    {
                        if ((int)p->data[i] >= 32 && (int)p->data[i] <=126)
                            tweakedPayload[i-j] = p->data[i];
                        else
                            tweakedPayload[i-j] = '.';
                    }
                    tweakedPayload[i-j] = '\0';
                    LogMessage("AppIdDbg %s\n", tweakedPayload);
                }
//#define DUMP_IN_HEX
#ifdef DUMP_IN_HEX
                LogMessage("AppIdDbg HEX data: (%d chars per line)\n",CHAR_DUMP_WIDTH);
                for (j=0; j<p->dsize; j+=CHAR_DUMP_WIDTH)
                {
                    for (i=j; i<p->dsize && i<(j+CHAR_DUMP_WIDTH); i++)
                    {
                        sprintf(&tweakedPayload[(i-j)*2], "%02x", (p->data)[i]);
                    }
                    // terminating '\0' provided by sprintf()
                    LogMessage("AppIdDbg %s\n", tweakedPayload);
                }
#endif
                snort_free(tweakedPayload); tweakedPayload = nullptr;
            }
        }
        if (p->flow)
        {
            LogMessage(
                "AppIdDbg \nAppIdDbg for p->flow=%p is_session_decrypted=%d direction=%d\n",
                p->flow, _dpd.streamAPI->is_session_decrypted(p->flow),
                _dpd.sessionAPI->get_ignore_direction(p->flow));
        }

        LogMessage("AppIdDbg ptrs.sp: %d\n", p->ptrs.sp);
        LogMessage("AppIdDbg ptrs.dp: %d\n", p->ptrs.dp);
        LogMessage("AppIdDbg orig_src_port: %d\n", p->orig_src_port);
        LogMessage("AppIdDbg rig_dst_port: %d\n", p->orig_dst_port);
        LogMessage("AppIdDbg payloadsize: %d\n", p->dsize);

        if ((p->packet_flags) & 0x00000080)
        {
            LogMessage("AppIdDbg direction: client\n");
        }
        else if ((p->packet_flags) & 0x00000040)
        {
            LogMessage("AppIdDbg direction: server\n");
        }
        else
        {
            LogMessage("AppIdDbg direction: unknown\n");
        }

        if ((p->packet_flags) & 0x00000001)
            LogMessage("AppIdDbg A rebuilt fragment\n");
        if ((p->packet_flags) & 0x00000002)
            LogMessage("AppIdDbg A rebuilt stream\n");
        if ((p->packet_flags) & 0x00000004)
            LogMessage(
                "AppIdDbg From an unestablished stream, traffic send one direction only\n");
        if ((p->packet_flags) & 0x00000008)
            LogMessage("AppIdDbg From an established stream\n");
        if ((p->packet_flags) & 0x00000010)
            LogMessage("AppIdDbg this packet has been queued for stream reassembly\n");
        if ((p->packet_flags) & 0x00000020)
            LogMessage("AppIdDbg packet completes the 3 way handshake\n");
        if ((p->packet_flags) & 0x00000040)
            LogMessage("AppIdDbg packet come from server side of a connection(tcp)\n");
        if ((p->packet_flags) & 0x00000080)
            LogMessage("AppIdDbg packet come from client side of a connection(tcp)\n");
        if ((p->packet_flags) & 0x00000100)
            LogMessage("AppIdDbg start of PDU\n");
        if ((p->packet_flags) & 0x00000200)
            LogMessage("AppIdDbg end of PDU\n");
        if ((p->packet_flags) & 0x00800000)
            LogMessage("AppIdDbg packet has new size\n");
    }
}

#else
#define printSnortPacket(SFSnortPacket_ptr)
#endif

void fwAppIdInit()
{
    /* init globals for snortId compares */
    snortId_for_ftp      = FindProtocolReference("ftp");
    snortId_for_ftp_data = FindProtocolReference("ftp-data");
    snortId_for_imap     = FindProtocolReference("imap");
    snortId_for_pop3     = FindProtocolReference("pop3");
    snortId_for_smtp     = FindProtocolReference("smtp");
    snortId_for_http2    = FindProtocolReference("http2");
}

void fwAppIdSearch(Packet* p)
{
    AppIdData* session;
    IpProtocol protocol;
    AppId tpAppId = 0;
    AppId serviceAppId = 0;
    AppId ClientAppId = 0;
    AppId payloadAppId = 0;
    bool isTpAppidDiscoveryDone = false;
    uint64_t flow_flags;
    int direction;
    const sfip_t* ip;
    uint16_t port;
    size_t size;
    int tp_confidence;
    AppId* tp_proto_list;
    ThirdPartyAppIDAttributeData* tp_attribute_data;
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;
    bool is_decrypted;
    bool is_rebuilt;
    bool is_http2;

    app_id_raw_packet_count++;

    if (!p->flow)
    {
        app_id_ignored_packet_count++;
        return;
    }

    is_decrypted = p->flow->is_proxied();
    is_rebuilt   = p->is_rebuilt();
// FIXIT-M - Need to convert this _dpd stream api call to the correct snort++ method
#ifdef REMOVED_WHILE_NOT_IN_USE
    is_http2     = _dpd.streamAPI->is_session_http2(p->flow);
#else
    is_http2     = false;
#endif
    if (is_http2)
    {
        session = getAppIdData(p->flow);
        if (session)
            session->is_http2 = true;
        if (!is_rebuilt)
        {
            // For HTTP/2, we only want to look at the ones that are rebuilt from
            // Stream / HTTP Inspect as HTTP/1 packets.
            app_id_ignored_packet_count++;
            return;
        }
    }
    else    // not HTTP/2
    {
        if (is_rebuilt && !is_decrypted)
        {
            session = getAppIdData(p->flow);
            if (session && session->hsession && session->hsession->get_offsets_from_rebuilt)
            {
                getOffsetsFromRebuilt(p, session->hsession);
                if (app_id_debug_session_flag)
                    LogMessage(
                        "AppIdDbg %s offsets from rebuilt packet: uri: %u-%u cookie: %u-%u\n",
                        app_id_debug_session, session->hsession->uriOffset,
                        session->hsession->uriEndOffset, session->hsession->cookieOffset,
                        session->hsession->cookieEndOffset);
            }
            app_id_ignored_packet_count++;
            return;
        }
    }

    session = appSharedGetData(p);
    if (session)
    {
        if (session->common.fsf_type.flow_type == APPID_SESSION_TYPE_IGNORE)
            return;
        if (session->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)
        {
            protocol = session->proto;
            session->ssn = p->flow;
        }
        else if (p->is_tcp())
            protocol = IpProtocol::TCP;
        else
            protocol = IpProtocol::UDP;

        ip = p->ptrs.ip_api.get_src();
        if (session->common.initiator_port)
            direction = (session->common.initiator_port == p->ptrs.sp) ? APP_ID_FROM_INITIATOR :
                APP_ID_FROM_RESPONDER;
        else
            direction = (sfip_fast_equals_raw(ip, &session->common.initiator_ip)) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }
    else
    {
        if (p->is_tcp())
            protocol = IpProtocol::TCP;

        else if (p->is_udp())
            protocol = IpProtocol::UDP;

        else if ( p->is_ip4() || p->is_ip6() )
            protocol = p->get_ip_proto_next();

        else
            return;

        // FIXIT - L Refactor to use direction symbols defined by snort proper
        direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    app_id_debug_session_flag = fwAppIdDebugCheck(p->flow, session, app_id_debug_flag,
        &app_id_debug_info, app_id_debug_session, direction);
    //if (app_id_debug_session_flag)
    //    LogMessage("AppIdDbg %s flag:%08x,decrypt:%s,http2:%s\n", app_id_debug_session,
    //                p->packet_flags, is_decrypted?"T":"F", is_http2?"T":"F");

    // fwAppIdSearch() is a top-level function that is called by AppIdProcess().
    // At this point, we know that we need to use the current active config -
    // pAppidActiveConfig. This function uses pAppidActiveConfig and passes it
    // to all the functions that need to look at AppId config.
    flow_flags = isSessionMonitored(p, direction, session);
    if (!(flow_flags & (APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED)))
    {
        if (!session)
        {
            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
                APPID_SESSION_BIDIRECTIONAL_CHECKED)
            {
                // FIXIT-M: This _dpd call needs to be convert to correct snort++ call
                // static THREAD_LOCAL APPID_SESSION_STRUCT_FLAG ignore_fsf {
                // APPID_SESSION_TYPE_IGNORE };

                // _dpd.sessionAPI->set_application_data(p->flow, PP_APP_ID, &ignore_fsf,
                //     nullptr);
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s not monitored\n", app_id_debug_session);
            }
            else
            {
                AppIdData* tmp_session;

                tmp_session = (decltype(tmp_session))snort_calloc(sizeof(AppIdData));

                tmp_session->common.fsf_type.flow_type = APPID_SESSION_TYPE_TMP;
                tmp_session->common.flags = flow_flags;
                ip = (direction == APP_ID_FROM_INITIATOR) ?
                    p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
                tmp_session->common.initiator_ip = *ip;
                if ( (protocol == IpProtocol::TCP || protocol == IpProtocol::UDP ) &&
                    p->ptrs.sp != p->ptrs.dp )
                {
                    tmp_session->common.initiator_port = (direction == APP_ID_FROM_INITIATOR) ?
                        p->ptrs.sp : p->ptrs.dp;
                }
                else
                    tmp_session->common.initiator_port = 0;
                tmp_session->common.policyId = appIdPolicyId;
                p->flow->set_application_data(tmp_session);
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s unknown monitoring\n", app_id_debug_session);
            }
        }
        else
        {
            session->common.flags = flow_flags;
            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
                APPID_SESSION_BIDIRECTIONAL_CHECKED)
                session->common.fsf_type.flow_type = APPID_SESSION_TYPE_IGNORE;
            session->common.policyId = appIdPolicyId;
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s not monitored\n", app_id_debug_session);
        }
        return;
    }

    if (!session || session->common.fsf_type.flow_type == APPID_SESSION_TYPE_TMP)
    {
        /* This call will free the existing temporary session, if there is one */
        session = appSharedCreateData(p, protocol, direction);
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s new session\n", app_id_debug_session);
    }

    app_id_processed_packet_count++;
    session->session_packet_count++;

    if (direction == APP_ID_FROM_INITIATOR)
        session->stats.initiatorBytes += p->pkth->pktlen;
    else
        session->stats.responderBytes += p->pkth->pktlen;

    session->common.flags = flow_flags;
    session->common.policyId = appIdPolicyId;

    tpAppId = session->tpAppId;

    session->common.policyId = appIdPolicyId;

    if (getAppIdFlag(session, APPID_SESSION_IGNORE_FLOW))
    {
        if (app_id_debug_session_flag && !getAppIdFlag(session, APPID_SESSION_IGNORE_FLOW_LOGGED))
        {
            setAppIdFlag(session, APPID_SESSION_IGNORE_FLOW_LOGGED);
            LogMessage("AppIdDbg %s Ignoring connection with service %d\n",
                app_id_debug_session, session->serviceAppId);
        }
        return;
    }

    if (p->packet_flags & PKT_STREAM_ORDER_BAD)
        setAppIdFlag(session, APPID_SESSION_OOO);

    else if ( p->is_tcp() && p->ptrs.tcph )
    {
        const auto* tcph = p->ptrs.tcph;
        if ( tcph->is_rst() && session->previous_tcp_flags == TH_SYN )
        {
            AppIdServiceIDState* id_state;

            setAppIdFlag(session, APPID_SESSION_SYN_RST);
            if (sfip_is_set(&session->service_ip))
            {
                ip = &session->service_ip;
                port = session->service_port;
            }
            else
            {
                ip = p->ptrs.ip_api.get_src();
                port = p->ptrs.sp;
            }

            id_state = AppIdGetServiceIDState(ip, IpProtocol::TCP, port,
                AppIdServiceDetectionLevel(
                session));

            if (id_state)
            {
                if (!id_state->reset_time)
                    id_state->reset_time = packet_time();
                else if ((packet_time() - id_state->reset_time) >= 60)
                {
                    // FIXIT-H ip's on the packet are const
                    // AppIdRemoveServiceIDState(ip, IpProtocol::TCP, port,
                    // AppIdServiceDetectionLevel(session));
                    setAppIdFlag(session, APPID_SESSION_SERVICE_DELETED);
                }
            }
        }

        session->previous_tcp_flags = p->ptrs.tcph->th_flags;
    }

    /*HostPort based AppId.  */
    if (!(session->scan_flags & SCAN_HOST_PORT_FLAG))
    {
        HostPortVal* hv;

        session->scan_flags |= SCAN_HOST_PORT_FLAG;
        if (direction == APP_ID_FROM_INITIATOR)
        {
            ip = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
        }
        else
        {
            ip = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
        }

        if ((hv = hostPortAppCacheFind(ip, port, protocol, pConfig)))
        {
            switch (hv->type)
            {
            case 1:
                session->ClientAppId = hv->appId;
                session->rnaClientState = RNA_STATE_FINISHED;
                break;
            case 2:
                session->payloadAppId = hv->appId;
                break;
            default:
                session->serviceAppId = hv->appId;
                synchAppIdWithSnortId(hv->appId, p, session, pConfig);
                session->rnaServiceState = RNA_STATE_FINISHED;
                session->rnaClientState = RNA_STATE_FINISHED;
                setAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED);
                if (thirdparty_appid_module)
                    thirdparty_appid_module->session_delete(session->tpsession, 1);
                session->tpsession = nullptr;
            }
        }
    }

    checkRestartAppDetection(session);

    //restart inspection by 3rd party
    if (!getAppIdFlag(session, APPID_SESSION_NO_TPI))
    {
        if (TPIsAppIdDone(session->tpsession) && getAppIdFlag(session,
            APPID_SESSION_HTTP_SESSION) && p->dsize)
        {
            if (session->tpReinspectByInitiator)
            {
                clearAppIdFlag(session, APPID_SESSION_APP_REINSPECT);
                if (direction == APP_ID_FROM_RESPONDER)
                    session->tpReinspectByInitiator = 0; //toggle at OK response
            }
            else if (direction == APP_ID_FROM_INITIATOR)
            {
                session->tpReinspectByInitiator = 1;     //once per request
                setAppIdFlag(session, APPID_SESSION_APP_REINSPECT);
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s 3rd party allow reinspect http\n",
                        app_id_debug_session);
                session->appHttpFieldClear();
            }
        }
    }

    if (session->tpAppId == APP_ID_SSH && session->payloadAppId != APP_ID_SFTP &&
        session->session_packet_count >= MIN_SFTP_PACKET_COUNT && session->session_packet_count <
        MAX_SFTP_PACKET_COUNT)
    {
        if ( p->ptrs.ip_api.tos() == 8 )
        {
            session->payloadAppId = APP_ID_SFTP;
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s data is SFTP\n", app_id_debug_session);
        }
    }

    Profile tpPerfStats_profile_context(tpPerfStats);

    /*** Start of third-party processing. ***/
    if (thirdparty_appid_module &&
        !getAppIdFlag(session, APPID_SESSION_NO_TPI) &&
        (!TPIsAppIdDone(session->tpsession) ||
        getAppIdFlag(session, APPID_SESSION_APP_REINSPECT | APPID_SESSION_APP_REINSPECT_SSL)))
    {
        // First SSL decrypted packet is now being inspected. Reset the flag so that SSL decrypted
        // traffic
        // gets processed like regular traffic from next packet onwards
        if (getAppIdFlag(session, APPID_SESSION_APP_REINSPECT_SSL))
        {
            clearAppIdFlag(session, APPID_SESSION_APP_REINSPECT_SSL);
        }
        if (p->dsize || pAppidActiveConfig->mod_config->tp_allow_probes)
        {
            if (protocol != IpProtocol::TCP || !p->dsize || (p->packet_flags &
                PKT_STREAM_ORDER_OK) ||
                pAppidActiveConfig->mod_config->tp_allow_probes)
            {
                {
                    Profile tpLibPerfStats_profile_context(tpLibPerfStats);
                    if (!session->tpsession)
                    {
                        if (!(session->tpsession = thirdparty_appid_module->session_create()))
                            FatalError(
                                "Could not allocate AppIdData->tpsession data");
                    }

                    printSnortPacket(p); // debug output of packet content
                    thirdparty_appid_module->session_process(session->tpsession, p, direction,
                        &tpAppId, &tp_confidence, &tp_proto_list, &tp_attribute_data);
                }

                isTpAppidDiscoveryDone = true;
                if (thirdparty_appid_module->session_state_get(session->tpsession) ==
                    TP_STATE_CLASSIFIED)
                    clearAppIdFlag(session, APPID_SESSION_APP_REINSPECT);

                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s 3rd party returned %d\n", app_id_debug_session,
                        tpAppId);

                if (appInfoEntryFlagGet(tpAppId, APPINFO_FLAG_IGNORE, pConfig))
                {
                    if (app_id_debug_session_flag)
                        LogMessage("AppIdDbg %s 3rd party ignored\n", app_id_debug_session);
                    if (getAppIdFlag(session, APPID_SESSION_HTTP_SESSION))
                        tpAppId = APP_ID_HTTP;
                    else
                        tpAppId = APP_ID_NONE;
                }

                // For now, third party can detect HTTP/2 (w/o metadata) for
                // some cases.  Treat it like HTTP w/ is_http2 flag set.
                if ((tpAppId == APP_ID_HTTP2) && (tp_confidence == 100))
                {
                    if (app_id_debug_session_flag)
                        LogMessage("AppIdDbg %s 3rd party saw HTTP/2\n", app_id_debug_session);
                    tpAppId = APP_ID_HTTP;
                    session->is_http2 = true;
                }

                // if the third-party appId must be treated as a client, do it now
                if (appInfoEntryFlagGet(tpAppId, APPINFO_FLAG_TP_CLIENT, pAppidActiveConfig))
                    session->ClientAppId = tpAppId;

                ProcessThirdPartyResults(p, session, tp_confidence, tp_proto_list,
                    tp_attribute_data);
#ifdef REMOVED_WHILE_NOT_IN_USE
                if (getAppIdFlag(session, APPID_SESSION_SSL_SESSION) &&
                    !(session->scan_flags & SCAN_SSL_HOST_FLAG))
                {
                    setSSLSquelch(p, 1, tpAppId);
                }
#endif
            }
            else
            {
                tpAppId = APP_ID_NONE;
                if (app_id_debug_session_flag && !getAppIdFlag(session,
                    APPID_SESSION_TPI_OOO_LOGGED))
                {
                    setAppIdFlag(session, APPID_SESSION_TPI_OOO_LOGGED);
                    LogMessage("AppIdDbg %s 3rd party packet out-of-order\n",
                        app_id_debug_session);
                }
            }

            if (thirdparty_appid_module->session_state_get(session->tpsession) ==
                TP_STATE_MONITORING)
            {
                thirdparty_appid_module->disable_flags(session->tpsession,
                    TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
                    TP_SESSION_FLAG_FUTUREFLOW);
            }

            if (tpAppId == APP_ID_SSL &&
                    (stream.get_application_protocol_id(p->flow) == snortId_for_ftp_data))
            {
                //  If we see SSL on an FTP data channel set tpAppId back
                //  to APP_ID_NONE so the FTP preprocessor picks up the flow.
                tpAppId = APP_ID_NONE;
            }

            if (tpAppId > APP_ID_NONE && (!getAppIdFlag(session, APPID_SESSION_APP_REINSPECT) ||
                session->payloadAppId > APP_ID_NONE))
            {
                AppId snorAppId;

                // if the packet is HTTP, then search for via pattern
                if (getAppIdFlag(session, APPID_SESSION_HTTP_SESSION) && session->hsession)
                {
                    snorAppId = APP_ID_HTTP;
                    //data should never be APP_ID_HTTP
                    if (tpAppId != APP_ID_HTTP)
                        session->tpPayloadAppId = tpAppId;

                    session->tpAppId = APP_ID_HTTP;

                    processHTTPPacket(p, session, direction, nullptr, pAppidActiveConfig);

                    if (TPIsAppIdAvailable(session->tpsession) && session->tpAppId == APP_ID_HTTP
                        && !getAppIdFlag(session, APPID_SESSION_APP_REINSPECT))
                    {
                        session->rnaClientState = RNA_STATE_FINISHED;
                        setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED |
                            APPID_SESSION_SERVICE_DETECTED);
                        session->rnaServiceState = RNA_STATE_FINISHED;
                        clearAppIdFlag(session, APPID_SESSION_CONTINUE);
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            ip = p->ptrs.ip_api.get_dst();
                            session->service_ip = *ip;
                            session->service_port = p->ptrs.dp;
                        }
                        else
                        {
                            ip = p->ptrs.ip_api.get_src();
                            session->service_ip = *ip;
                            session->service_port = p->ptrs.sp;
                        }
                    }
                }
                else if (getAppIdFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
                {
                    ExamineSslMetadata(p, session, pConfig);

                    uint16_t serverPort;
                    AppId porAppId;

                    serverPort = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.dp : p->ptrs.sp;

#ifdef REMOVED_WHILE_NOT_IN_USE
                    porAppId = getSslServiceAppId(serverPort);
#else
                    porAppId = serverPort;
#endif
                    if (tpAppId == APP_ID_SSL )
                    {
                        tpAppId = porAppId;

                        //SSL policy needs to determine IMAPS/POP3S etc before appId sees first
                        // server packet
                        session->portServiceAppId = porAppId;

                        if (app_id_debug_session_flag)
                            LogMessage("AppIdDbg %s SSL is service %d, portServiceAppId %d\n",
                                app_id_debug_session, tpAppId, session->portServiceAppId);
                    }
                    else
                    {
                        session->tpPayloadAppId = tpAppId;
                        tpAppId = porAppId;
                        if (app_id_debug_session_flag)
                            LogMessage("AppIdDbg %s SSL is %d\n", app_id_debug_session, tpAppId);
                    }
                    session->tpAppId = tpAppId;
                    snorAppId = APP_ID_SSL;
                }
                else
                {
                    //for non-http protocols, tp id is treated like serviceId

                    snorAppId = tpAppId;
                    session->tpAppId = tpAppId;
                }

                synchAppIdWithSnortId(snorAppId, p, session, pConfig);
            }
            else
            {
                if ( protocol != IpProtocol::TCP || !p->dsize ||
                    (p->packet_flags & (PKT_STREAM_ORDER_OK | PKT_STREAM_ORDER_BAD)))
                {
                    if (direction == APP_ID_FROM_INITIATOR)
                    {
                        session->init_tpPackets++;
                        checkTerminateTpModule(session->init_tpPackets, session);
                    }
                    else
                    {
                        session->resp_tpPackets++;
                        checkTerminateTpModule(session->resp_tpPackets, session);
                    }
                }
            }
        }
    }

    if (direction == APP_ID_FROM_RESPONDER && !getAppIdFlag(session,
        APPID_SESSION_PORT_SERVICE_DONE|APPID_SESSION_SYN_RST))
    {
        setAppIdFlag(session, APPID_SESSION_PORT_SERVICE_DONE);
        session->portServiceAppId = getPortServiceId(protocol, p->ptrs.sp, pConfig);
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s port service %d\n", app_id_debug_session,
                session->portServiceAppId);
    }

    /* Length-based detectors. */
    /* Only check if:
     *  - Port service didn't find anything (and we haven't yet either).
     *  - We haven't hit the max packets allowed for detector sequence matches.
     *  - Packet has data (we'll ignore 0-sized packets in sequencing). */
    if (   (session->portServiceAppId <= APP_ID_NONE)
        && (session->length_sequence.sequence_cnt < LENGTH_SEQUENCE_CNT_MAX)
        && (p->dsize > 0))
    {
        uint8_t index = session->length_sequence.sequence_cnt;
        session->length_sequence.proto = protocol;
        session->length_sequence.sequence_cnt++;
        session->length_sequence.sequence[index].direction = direction;
        session->length_sequence.sequence[index].length    = p->dsize;
        session->portServiceAppId = lengthAppCacheFind(&session->length_sequence, pConfig);
        if (session->portServiceAppId > APP_ID_NONE)
        {
            setAppIdFlag(session, APPID_SESSION_PORT_SERVICE_DONE);
        }
    }

    /* exceptions for rexec and any other service detector that needs to see SYN and SYN/ACK */
    if (getAppIdFlag(session, APPID_SESSION_REXEC_STDERR))
    {
        AppIdDiscoverService(p, direction, session, pConfig);
        if (session->serviceAppId == APP_ID_DNS &&
            pAppidActiveConfig->mod_config->dns_host_reporting &&
            session->dsession && session->dsession->host )
        {
            size = session->dsession->host_len;
            dns_host_scan_hostname((const u_int8_t*)session->dsession->host, size, &ClientAppId,
                &payloadAppId, &pConfig->serviceDnsConfig);
            setClientAppIdData(session, ClientAppId, nullptr);
        }
        else if (session->serviceAppId == APP_ID_RTMP)
            ExamineRtmpMetadata(session);
        else if (getAppIdFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
            ExamineSslMetadata(p, session, pConfig);
    }
    else if (protocol != IpProtocol::TCP || !p->dsize || (p->packet_flags & PKT_STREAM_ORDER_OK))
    {
        /*** Start of service discovery. ***/
        if (session->rnaServiceState != RNA_STATE_FINISHED)
        {
            Profile serviceMatchPerfStats_profile_context(serviceMatchPerfStats);

            uint32_t prevRnaServiceState;

            tpAppId = session->tpAppId;
            prevRnaServiceState = session->rnaServiceState;

            //decision to directly call validator or go through elaborate service_state tracking
            //is made once at the beginning of sesssion.
            if (session->rnaServiceState == RNA_STATE_NONE && p->dsize)
            {
                if ( p->flow->get_session_flags() & SSNFLAG_MIDSTREAM )
                {
                    // Unless it could be ftp control
                    if ( protocol == IpProtocol::TCP && (p->ptrs.sp == 21 || p->ptrs.dp == 21) &&
                        !(p->ptrs.tcph->is_fin() || p->ptrs.tcph->is_rst()) )
                    {
                        setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED |
                            APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                        if (!AddFTPServiceState(session))
                        {
                            setAppIdFlag(session, APPID_SESSION_CONTINUE);
                            if (p->ptrs.dp != 21)
                                setAppIdFlag(session, APPID_SESSION_RESPONDER_SEEN);
                        }
                        session->rnaServiceState = RNA_STATE_STATEFUL;
                    }
                    else
                    {
                        setAppIdFlag(session, APPID_SESSION_MID | APPID_SESSION_SERVICE_DETECTED);
                        session->rnaServiceState = RNA_STATE_FINISHED;
                    }
                }
                else if (TPIsAppIdAvailable(session->tpsession))
                {
                    if (tpAppId > APP_ID_NONE)
                    {
                        //tp has positively identified appId, Dig deeper only if sourcefire
                        // detector
                        //identifies additional information or flow is UDP reveresed.
                        if ((entry = appInfoEntryGet(tpAppId, pConfig))
                            && entry->svrValidator &&
                            ((entry->flags & APPINFO_FLAG_SERVICE_ADDITIONAL) ||
                            ((entry->flags & APPINFO_FLAG_SERVICE_UDP_REVERSED) && protocol ==
                            IpProtocol::UDP &&
                            getAppIdFlag(session, APPID_SESSION_INITIATOR_MONITORED |
                            APPID_SESSION_RESPONDER_MONITORED))))
                        {
                            AppIdFlowdataDeleteAllByMask(session,
                                APPID_SESSION_DATA_SERVICE_MODSTATE_BIT);

                            session->serviceData = entry->svrValidator;
                            session->rnaServiceState = RNA_STATE_STATEFUL;
                        }
                        else
                        {
                            stopRnaServiceInspection(p, session, direction);
                        }
                    }
                    else
                        session->rnaServiceState = RNA_STATE_STATEFUL;
                }
                else
                    session->rnaServiceState = RNA_STATE_STATEFUL;
            }

            //stop rna inspection as soon as tp has classified a valid AppId later in the session
            if (session->rnaServiceState == RNA_STATE_STATEFUL &&
                prevRnaServiceState == RNA_STATE_STATEFUL &&
                !getAppIdFlag(session, APPID_SESSION_NO_TPI) &&
                TPIsAppIdAvailable(session->tpsession) &&
                tpAppId > APP_ID_NONE  && tpAppId < SF_APPID_MAX)
            {
                entry = appInfoEntryGet(tpAppId, pConfig);

                if (entry && entry->svrValidator && !(entry->flags &
                    APPINFO_FLAG_SERVICE_ADDITIONAL))
                {
                    if (app_id_debug_session_flag)
                        LogMessage("AppIdDbg %s Stopping service detection\n",
                            app_id_debug_session);
                    stopRnaServiceInspection(p, session, direction);
                }
            }

            if (session->rnaServiceState == RNA_STATE_STATEFUL)
            {
                AppIdDiscoverService(p, direction, session, pConfig);
                isTpAppidDiscoveryDone = true;
                //to stop executing validator after service has been detected by RNA.
                if (getAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED |
                    APPID_SESSION_CONTINUE) == APPID_SESSION_SERVICE_DETECTED)
                    session->rnaServiceState = RNA_STATE_FINISHED;

                if (session->serviceAppId == APP_ID_DNS &&
                    pAppidActiveConfig->mod_config->dns_host_reporting &&
                    session->dsession && session->dsession->host  )
                {
                    size = session->dsession->host_len;
                    dns_host_scan_hostname((const u_int8_t*)session->dsession->host, size,
                        &ClientAppId, &payloadAppId, &pConfig->serviceDnsConfig);
                    setClientAppIdData(session, ClientAppId, nullptr);
                }
                else if (session->serviceAppId == APP_ID_RTMP)
                    ExamineRtmpMetadata(session);
                else if (getAppIdFlag(session, APPID_SESSION_SSL_SESSION) && session->tsession)
                    ExamineSslMetadata(p, session, pConfig);

                if (tpAppId <= APP_ID_NONE &&
                    getAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_IGNORE_HOST) ==
                    APPID_SESSION_SERVICE_DETECTED)
                {
                    synchAppIdWithSnortId(session->serviceAppId, p, session, pConfig);
                }
            }
        }
        /*** End of service discovery. ***/

        /*** Start of client discovery. ***/
        if (session->rnaClientState != RNA_STATE_FINISHED)
        {
            Profile clientMatchPerfStats_profile_context(clientMatchPerfStats);
            uint32_t prevRnaClientState = session->rnaClientState;
            bool was_http2 = session->is_http2;
            bool was_service = getAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED) ? true :
                false;

            //decision to directly call validator or go through elaborate service_state tracking
            //is made once at the beginning of sesssion.
            if (session->rnaClientState == RNA_STATE_NONE && p->dsize && direction ==
                APP_ID_FROM_INITIATOR)
            {
                if ( p->flow->get_session_flags() & SSNFLAG_MIDSTREAM )
                    session->rnaClientState = RNA_STATE_FINISHED;

                else if (TPIsAppIdAvailable(session->tpsession) && (tpAppId = session->tpAppId) >
                    APP_ID_NONE && tpAppId < SF_APPID_MAX)
                {
                    AppInfoTableEntry* entry;

                    if ((entry = appInfoEntryGet(tpAppId, pConfig)) && entry->clntValidator &&
                        ((entry->flags & APPINFO_FLAG_CLIENT_ADDITIONAL) ||
                        ((entry->flags & APPINFO_FLAG_CLIENT_USER) &&
                        getAppIdFlag(session, APPID_SESSION_DISCOVER_USER))))
                    {
                        //tp has positively identified appId, Dig deeper only if sourcefire
                        // detector
                        //identifies additional information
                        session->clientData = entry->clntValidator;
                        session->rnaClientState = RNA_STATE_DIRECT;
                    }
                    else
                    {
                        setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED);
                        session->rnaClientState = RNA_STATE_FINISHED;
                    }
                }
                else if (getAppIdFlag(session, APPID_SESSION_HTTP_SESSION))
                    session->rnaClientState = RNA_STATE_FINISHED;
                else
                    session->rnaClientState = RNA_STATE_STATEFUL;
            }

            //stop rna inspection as soon as tp has classified a valid AppId later in the session
            if ((session->rnaClientState == RNA_STATE_STATEFUL ||
                session->rnaClientState == RNA_STATE_DIRECT) &&
                session->rnaClientState == prevRnaClientState &&
                !getAppIdFlag(session, APPID_SESSION_NO_TPI) &&
                TPIsAppIdAvailable(session->tpsession) &&
                tpAppId > APP_ID_NONE  && tpAppId < SF_APPID_MAX)
            {
                entry = appInfoEntryGet(tpAppId, pConfig);

                if (!(entry && entry->clntValidator && entry->clntValidator ==
                    session->clientData && (entry->flags & (APPINFO_FLAG_CLIENT_ADDITIONAL|
                    APPINFO_FLAG_CLIENT_USER))))
                {
                    session->rnaClientState = RNA_STATE_FINISHED;
                    setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED);
                }
            }

            if (session->rnaClientState == RNA_STATE_DIRECT)
            {
                int ret = CLIENT_APP_INPROCESS;

                if (direction == APP_ID_FROM_INITIATOR)
                {
                    /* get out if we've already tried to validate a client app */
                    if (!getAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED))
                    {
                        ret = RunClientDetectors(session, p, direction, pConfig);
                    }
                }
                else if (session->rnaServiceState != RNA_STATE_STATEFUL &&
                    getAppIdFlag(session, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
                {
                    ret = RunClientDetectors(session, p, direction, pConfig);
                }

                switch (ret)
                {
                case CLIENT_APP_INPROCESS:
                    break;
                default:
                    session->rnaClientState = RNA_STATE_FINISHED;
                    break;
                }
            }
            else if (session->rnaClientState == RNA_STATE_STATEFUL)
            {
                AppIdDiscoverClientApp(p, direction, session, pConfig);
                isTpAppidDiscoveryDone = true;
                if (session->candidate_client_list != nullptr)
                {
                    if (sflist_count(session->candidate_client_list) > 0)
                    {
                        int ret = 0;
                        if (direction == APP_ID_FROM_INITIATOR)
                        {
                            /* get out if we've already tried to validate a client app */
                            if (!getAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED))
                            {
                                ret = RunClientDetectors(session, p, direction, pConfig);
                            }
                        }
                        else if (session->rnaServiceState != RNA_STATE_STATEFUL &&
                            getAppIdFlag(session, APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
                        {
                            ret = RunClientDetectors(session, p, direction, pConfig);
                        }
                        if (ret < 0)
                            setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED);
                    }
                    else
                    {
                        setAppIdFlag(session, APPID_SESSION_CLIENT_DETECTED);
                    }
                }
            }
            if (app_id_debug_session_flag)
                if (!was_http2 && session->is_http2)
                    LogMessage("AppIdDbg %s Got a preface for HTTP/2\n", app_id_debug_session);

            if (!was_service && getAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED))
                synchAppIdWithSnortId(session->serviceAppId, p, session, pConfig);
        }
        /*** End of client discovery. ***/

        setAppIdFlag(session, APPID_SESSION_ADDITIONAL_PACKET);
    }
    else
    {
        if (app_id_debug_session_flag && p->dsize &&
            !getAppIdFlag(session, APPID_SESSION_OOO_LOGGED))
        {
            setAppIdFlag(session, APPID_SESSION_OOO_LOGGED);
            LogMessage("AppIdDbg %s packet out-of-order\n", app_id_debug_session);
        }
    }

    serviceAppId = pickServiceAppId(session);
    payloadAppId = pickPayloadId(session);

    if (serviceAppId > APP_ID_NONE)
    {
        if (getAppIdFlag(session, APPID_SESSION_DECRYPTED))
        {
            if (session->miscAppId == APP_ID_NONE)
                updateEncryptedAppId(session, serviceAppId);
        }
// FIXIT-M: Need to determine what api to use for this _dpd function
#if 1
        UNUSED(isTpAppidDiscoveryDone);
#else
        else if (isTpAppidDiscoveryDone && isSslServiceAppId(serviceAppId) &&
            _dpd.isSSLPolicyEnabled(nullptr))
            setAppIdFlag(session, APPID_SESSION_CONTINUE);
#endif
    }

// FIXIT-M: Need to determine what api to use for this _dpd function
#ifdef REMOVED_WHILE_NOT_IN_USE
    _dpd.streamAPI->set_application_id(p->flow, serviceAppId, pickClientAppId(session),
        payloadAppId, pickMiscAppId(session));
#endif

    /* Set the field that the Firewall queries to see if we have a search engine. */
    if (session->search_support_type == SEARCH_SUPPORT_TYPE_UNKNOWN && payloadAppId > APP_ID_NONE)
    {
        uint flags = appInfoEntryFlagGet(payloadAppId, APPINFO_FLAG_SEARCH_ENGINE |
            APPINFO_FLAG_SUPPORTED_SEARCH, pConfig);
        session->search_support_type =
            (flags & APPINFO_FLAG_SEARCH_ENGINE) ?
            ((flags & APPINFO_FLAG_SUPPORTED_SEARCH) ? SUPPORTED_SEARCH_ENGINE :
            UNSUPPORTED_SEARCH_ENGINE )
            : NOT_A_SEARCH_ENGINE;
        if (app_id_debug_session_flag)
        {
            const char* typeString;
            switch ( session->search_support_type )
            {
            case NOT_A_SEARCH_ENGINE: typeString = "NOT_A_SEARCH_ENGINE"; break;
            case SUPPORTED_SEARCH_ENGINE: typeString = "SUPPORTED_SEARCH_ENGINE"; break;
            case UNSUPPORTED_SEARCH_ENGINE: typeString = "UNSUPPORTED_SEARCH_ENGINE"; break;
            default: typeString = "unknown"; break;
            }

            LogMessage("AppIdDbg %s appId: %u (safe)search_support_type=%s\n",
                app_id_debug_session, payloadAppId, typeString);
        }
    }

    if ( serviceAppId !=  APP_ID_NONE )
    {
        if ( payloadAppId != APP_ID_NONE && payloadAppId != session->pastIndicator)
        {
            session->pastIndicator = payloadAppId;
            checkSessionForAFIndicator(p, direction, pConfig, (ApplicationId)payloadAppId);
        }

        if (session->payloadAppId == APP_ID_NONE && session->pastForecast != serviceAppId &&
            session->pastForecast != APP_ID_UNKNOWN)
        {
            session->pastForecast = checkSessionForAFForecast(session, p, direction, pConfig,
                (ApplicationId)serviceAppId);
        }
    }
}

static inline void pickHttpXffAddress(Packet*, AppIdData* appIdSession,
    ThirdPartyAppIDAttributeData* attribute_data)
{
    int i;
    static const char* defaultXffPrecedence[] =
    {
        HTTP_XFF_FIELD_X_FORWARDED_FOR,
        HTTP_XFF_FIELD_TRUE_CLIENT_IP
    };

    // XFF precedence configuration cannot change for a session. Do not get it again if we already
    // got it.
// FIXIT-M:
#ifdef REMOVED_WHILE_NOT_IN_USE
    if (!appIdSession->hsession->xffPrecedence)
        appIdSession->hsession->xffPrecedence = _dpd.sessionAPI->get_http_xff_precedence(
            p->flow, p->packet_flags, &appIdSession->hsession->numXffFields);
#endif

    if (!appIdSession->hsession->xffPrecedence)
    {
        appIdSession->hsession->xffPrecedence = defaultXffPrecedence;
        appIdSession->hsession->numXffFields = sizeof(defaultXffPrecedence) /
            sizeof(defaultXffPrecedence[0]);
    }

    if (app_id_debug_session_flag)
    {
        for (i = 0; i < attribute_data->numXffFields; i++)
            LogMessage("AppIdDbg %s %s : %s\n", app_id_debug_session,
                attribute_data->xffFieldValue[i].field, attribute_data->xffFieldValue[i].value);
    }

    // xffPrecedence array is sorted based on precedence
    for (i = 0; (i < appIdSession->hsession->numXffFields) &&
        appIdSession->hsession->xffPrecedence[i]; i++)
    {
        int j;
        for (j = 0; j < attribute_data->numXffFields; j++)
        {
            if (appIdSession->hsession->xffAddr)
                sfip_free(appIdSession->hsession->xffAddr);

            if (strncasecmp(attribute_data->xffFieldValue[j].field,
                appIdSession->hsession->xffPrecedence[i], UINT8_MAX) == 0)
            {
                char* tmp = strchr(attribute_data->xffFieldValue[j].value, ',');
                SFIP_RET status;

                if (!tmp)
                {
                    appIdSession->hsession->xffAddr = sfip_alloc(
                        attribute_data->xffFieldValue[j].value, &status);
                }
                // For a comma-separated list of addresses, pick the first address
                else
                {
                    attribute_data->xffFieldValue[j].value[tmp -
                    attribute_data->xffFieldValue[j].value] = '\0';
                    appIdSession->hsession->xffAddr = sfip_alloc(
                        attribute_data->xffFieldValue[j].value, &status);
                }
                break;
            }
        }
        if (appIdSession->hsession->xffAddr)
            break;
    }
}

static inline void ProcessThirdPartyResults(Packet* p, AppIdData* appIdSession, int
    confidence, AppId* proto_list, ThirdPartyAppIDAttributeData* attribute_data)
{
    int size;
    AppId serviceAppId = 0;
    AppId ClientAppId = 0;
    AppId payloadAppId = 0;
    AppId referredPayloadAppId = 0;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (ThirdPartyAppIDFoundProto(APP_ID_EXCHANGE, proto_list))
    {
        if (!appIdSession->payloadAppId)
            appIdSession->payloadAppId = APP_ID_EXCHANGE;
    }

    if (ThirdPartyAppIDFoundProto(APP_ID_HTTP, proto_list))
    {
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s flow is HTTP\n", app_id_debug_session);
        setAppIdFlag(appIdSession, APPID_SESSION_HTTP_SESSION);
    }
    if (ThirdPartyAppIDFoundProto(APP_ID_SPDY, proto_list))
    {
        if (app_id_debug_session_flag)
            LogMessage("AppIdDbg %s flow is SPDY\n", app_id_debug_session);

        setAppIdFlag(appIdSession, APPID_SESSION_HTTP_SESSION | APPID_SESSION_SPDY_SESSION);
    }

    if (getAppIdFlag(appIdSession, APPID_SESSION_HTTP_SESSION))
    {
        if (!appIdSession->hsession)
        {
            appIdSession->hsession = (httpSession*)snort_calloc(sizeof(httpSession));
            memset(ptype_scan_counts, 0, 7 * sizeof(ptype_scan_counts[0]));
        }

        if (getAppIdFlag(appIdSession, APPID_SESSION_SPDY_SESSION))
        {
            if (attribute_data->spdyRequesHost)
            {
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s SPDY host is %s\n", app_id_debug_session,
                        attribute_data->spdyRequesHost);
                if (appIdSession->hsession->host)
                {
                    snort_free(appIdSession->hsession->host);
                    appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->host = snort_strdup(attribute_data->spdyRequesHost);
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->spdyRequestPath)
            {
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s SPDY URI is %s\n", app_id_debug_session,
                        attribute_data->spdyRequestPath);
                if (appIdSession->hsession->uri)
                {
                    snort_free(appIdSession->hsession->uri);
                    appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->uri = snort_strdup(attribute_data->spdyRequestPath);
            }
            if (attribute_data->spdyRequestScheme &&
                attribute_data->spdyRequesHost &&
                attribute_data->spdyRequestPath)
            {
                static const char httpsScheme[] = "https";
                static const char httpScheme[] = "http";
                const char* scheme;

                if (appIdSession->hsession->url)
                {
                    snort_free(appIdSession->hsession->url);
                    appIdSession->hsession->chp_finished = 0;
                }
                if (getAppIdFlag(appIdSession, APPID_SESSION_DECRYPTED)
                    && memcmp(attribute_data->spdyRequestScheme, httpScheme, sizeof(httpScheme)-
                    1) == 0)
                {
                    scheme = httpsScheme;
                }
                else
                {
                    scheme = attribute_data->spdyRequestScheme;
                }

                size = strlen(scheme) +
                    strlen(attribute_data->spdyRequesHost) +
                    strlen(attribute_data->spdyRequestPath) +
                    sizeof("://");    // see sprintf() format
                appIdSession->hsession->url = (char*)snort_calloc(size);
                sprintf(appIdSession->hsession->url, "%s://%s%s",
                    scheme, attribute_data->spdyRequesHost, attribute_data->spdyRequestPath);
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->spdyRequestScheme)
            {
                snort_free(attribute_data->spdyRequestScheme);
                attribute_data->spdyRequestScheme = nullptr;
            }
            if (attribute_data->spdyRequesHost)
            {
                snort_free(attribute_data->spdyRequesHost);
                attribute_data->spdyRequesHost = nullptr;
            }
            if (attribute_data->spdyRequestPath)
            {
                snort_free(attribute_data->spdyRequestPath);
                attribute_data->spdyRequestPath = nullptr;
            }
        }
        else
        {
            if (attribute_data->httpRequesHost)
            {
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s HTTP host is %s\n", app_id_debug_session,
                        attribute_data->httpRequesHost);
                if (appIdSession->hsession->host)
                {
                    snort_free(appIdSession->hsession->host);
                    if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->host = attribute_data->httpRequesHost;
                attribute_data->httpRequesHost = nullptr;
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequesUrl)
            {
                static const char httpScheme[] = "http://";

                if (appIdSession->hsession->url)
                {
                    snort_free(appIdSession->hsession->url);
                    if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }

                //change http to https if session was decrypted.
                if (getAppIdFlag(appIdSession, APPID_SESSION_DECRYPTED)
                    &&
                    memcmp(attribute_data->httpRequesUrl, httpScheme, sizeof(httpScheme)-1) == 0)
                {
                    appIdSession->hsession->url =
                        (char*)snort_calloc(strlen(attribute_data->httpRequesUrl) + 2);

                    if (appIdSession->hsession->url)
                        sprintf(appIdSession->hsession->url, "https://%s",
                            attribute_data->httpRequesUrl + sizeof(httpScheme)-1);

                    snort_free(attribute_data->httpRequesUrl);
                    attribute_data->httpRequesUrl = nullptr;
                }
                else
                {
                    appIdSession->hsession->url = attribute_data->httpRequesUrl;
                    attribute_data->httpRequesUrl = nullptr;
                }

                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
            if (attribute_data->httpRequestUri)
            {
                if (appIdSession->hsession->uri)
                {
                    snort_free(appIdSession->hsession->uri);
                    if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                        appIdSession->hsession->chp_finished = 0;
                }
                appIdSession->hsession->uri = attribute_data->httpRequestUri;
                appIdSession->hsession->uriOffset = attribute_data->httpRequestUriOffset;
                appIdSession->hsession->uriEndOffset = attribute_data->httpRequestUriEndOffset;
                attribute_data->httpRequestUri = nullptr;
                attribute_data->httpRequestUriOffset = 0;
                attribute_data->httpRequestUriEndOffset = 0;
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s uri (%u-%u) is %s\n", app_id_debug_session,
                        appIdSession->hsession->uriOffset, appIdSession->hsession->uriEndOffset,
                        appIdSession->hsession->uri);
            }
        }
        if (attribute_data->httpRequestVia)
        {
            if (appIdSession->hsession->via)
            {
                snort_free(appIdSession->hsession->via);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->via = attribute_data->httpRequestVia;
            attribute_data->httpRequestVia = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        else if (attribute_data->httpResponseVia)
        {
            if (appIdSession->hsession->via)
            {
                snort_free(appIdSession->hsession->via);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->via = attribute_data->httpResponseVia;
            attribute_data->httpResponseVia = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (attribute_data->httpRequestUserAgent)
        {
            if (appIdSession->hsession->useragent)
            {
                snort_free(appIdSession->hsession->useragent);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->useragent = attribute_data->httpRequestUserAgent;
            attribute_data->httpRequestUserAgent = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        // Check to see if third party discovered HTTP/2.
        //  - once it supports it...
        if (attribute_data->httpResponseVersion)
        {
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s HTTP response version is %s\n", app_id_debug_session,
                    attribute_data->httpResponseVersion);
            if (strncmp(attribute_data->httpResponseVersion, "HTTP/2", 6) == 0)
            {
                if (app_id_debug_session_flag)
                    LogMessage("AppIdDbg %s 3rd party detected and parsed HTTP/2\n",
                        app_id_debug_session);
                appIdSession->is_http2 = true;
            }
            snort_free(attribute_data->httpResponseVersion);
            attribute_data->httpResponseVersion = nullptr;
        }
        if (attribute_data->httpResponseCode)
        {
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s HTTP response code is %s\n", app_id_debug_session,
                    attribute_data->httpResponseCode);
            if (appIdSession->hsession->response_code)
            {
                snort_free(appIdSession->hsession->response_code);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->response_code = attribute_data->httpResponseCode;
            attribute_data->httpResponseCode = nullptr;
        }
        // Check to see if we've got an upgrade to HTTP/2 (if enabled).
        //  - This covers the "without prior knowledge" case (i.e., the client
        //    asks the server to upgrade to HTTP/2).
        if (attribute_data->httpResponseUpgrade)
        {
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s HTTP response upgrade is %s\n", app_id_debug_session,
                    attribute_data->httpResponseUpgrade);
            if (pAppidActiveConfig->mod_config->http2_detection_enabled)
                if (appIdSession->hsession->response_code && (strncmp(
                    appIdSession->hsession->response_code, "101", 3) == 0))
                    if (strncmp(attribute_data->httpResponseUpgrade, "h2c", 3) == 0)
                    {
                        if (app_id_debug_session_flag)
                            LogMessage("AppIdDbg %s Got an upgrade to HTTP/2\n",
                                app_id_debug_session);
                        appIdSession->is_http2 = true;
                    }
            snort_free(attribute_data->httpResponseUpgrade);
            attribute_data->httpResponseUpgrade = nullptr;
        }
        if (!pAppidActiveConfig->mod_config->referred_appId_disabled &&
            attribute_data->httpRequestReferer)
        {
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s referrer is %s\n", app_id_debug_session,
                    attribute_data->httpRequestReferer);
            if (appIdSession->hsession->referer)
            {
                snort_free(appIdSession->hsession->referer);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->referer = attribute_data->httpRequestReferer;
            attribute_data->httpRequestReferer = nullptr;
        }
        if (attribute_data->httpRequestCookie)
        {
            if (appIdSession->hsession->cookie)
            {
                snort_free(appIdSession->hsession->cookie);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->cookie = attribute_data->httpRequestCookie;
            appIdSession->hsession->cookieOffset = attribute_data->httpRequestCookieOffset;
            appIdSession->hsession->cookieEndOffset = attribute_data->httpRequestCookieEndOffset;
            attribute_data->httpRequestCookie = nullptr;
            attribute_data->httpRequestCookieOffset = 0;
            attribute_data->httpRequestCookieEndOffset = 0;
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s cookie (%u-%u) is %s\n", app_id_debug_session,
                    appIdSession->hsession->cookieOffset, appIdSession->hsession->cookieEndOffset,
                    appIdSession->hsession->cookie);
        }
        if (attribute_data->httpResponseContent)
        {
            if (appIdSession->hsession->content_type)
            {
                snort_free(appIdSession->hsession->content_type);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->content_type = attribute_data->httpResponseContent;
            attribute_data->httpResponseContent = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_CONTENT_TYPE_FLAG;
        }
        if (ptype_scan_counts[LOCATION_PT] && attribute_data->httpResponseLocation)
        {
            if (appIdSession->hsession->location)
            {
                snort_free(appIdSession->hsession->location);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->location = attribute_data->httpResponseLocation;
            attribute_data->httpResponseLocation = nullptr;
        }
        if (attribute_data->httpRequestBody)
        {
            if (app_id_debug_session_flag)
                LogMessage("AppIdDbg %s got a request body %s\n", app_id_debug_session,
                    attribute_data->httpRequestBody);
            if (appIdSession->hsession->req_body)
            {
                snort_free(appIdSession->hsession->req_body);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->req_body = attribute_data->httpRequestBody;
            attribute_data->httpRequestBody = nullptr;
        }
        if (ptype_scan_counts[BODY_PT] && attribute_data->httpResponseBody)
        {
            if (appIdSession->hsession->body)
            {
                snort_free(appIdSession->hsession->body);
                if (!getAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT))
                    appIdSession->hsession->chp_finished = 0;
            }
            appIdSession->hsession->body = attribute_data->httpResponseBody;
            attribute_data->httpResponseBody = nullptr;
        }
        if (attribute_data->numXffFields)
        {
            pickHttpXffAddress(p, appIdSession, attribute_data);
        }
        if (!appIdSession->hsession->chp_finished || appIdSession->hsession->chp_hold_flow)
        {
            setAppIdFlag(appIdSession, APPID_SESSION_CHP_INSPECTING);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_attr_set(appIdSession->tpsession,
                    TP_ATTR_CONTINUE_MONITORING);
        }
        if (attribute_data->httpResponseServer)
        {
            if (appIdSession->hsession->server)
                snort_free(appIdSession->hsession->server);
            appIdSession->hsession->server = attribute_data->httpResponseServer;
            attribute_data->httpResponseServer = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_VENDOR_FLAG;
        }
        if (attribute_data->httpRequestXWorkingWith)
        {
            if (appIdSession->hsession->x_working_with)
                snort_free(appIdSession->hsession->x_working_with);
            appIdSession->hsession->x_working_with = attribute_data->httpRequestXWorkingWith;
            attribute_data->httpRequestXWorkingWith = nullptr;
            appIdSession->scan_flags |= SCAN_HTTP_XWORKINGWITH_FLAG;
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_RTMP, proto_list) ||
        ThirdPartyAppIDFoundProto(APP_ID_RTSP, proto_list))
    {
        if (!appIdSession->hsession)
            appIdSession->hsession = (httpSession*)snort_calloc(sizeof(httpSession));

        if (!appIdSession->hsession->url)
        {
            if (attribute_data->httpRequesUrl)
            {
                appIdSession->hsession->url = attribute_data->httpRequesUrl;
                attribute_data->httpRequesUrl = nullptr;
                appIdSession->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
        }

        if (!pAppidActiveConfig->mod_config->referred_appId_disabled &&
            !appIdSession->hsession->referer)
        {
            if (attribute_data->httpRequestReferer)
            {
                appIdSession->hsession->referer = attribute_data->httpRequestReferer;
                attribute_data->httpRequestReferer = nullptr;
            }
        }

        if (appIdSession->hsession->url || (confidence == 100 &&
            appIdSession->session_packet_count > pAppidActiveConfig->mod_config->rtmp_max_packets))
        {
            if (appIdSession->hsession->url)
            {
                if (((getAppIdFromUrl(nullptr, appIdSession->hsession->url, nullptr,
                    appIdSession->hsession->referer, &ClientAppId, &serviceAppId,
                    &payloadAppId, &referredPayloadAppId, 1, &pConfig->detectorHttpConfig)) ||
                    (getAppIdFromUrl(nullptr, appIdSession->hsession->url, nullptr,
                    appIdSession->hsession->referer, &ClientAppId, &serviceAppId,
                    &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig))) == 1)
                {
                    // do not overwrite a previously-set client or service
                    if (appIdSession->ClientAppId <= APP_ID_NONE)
                        setClientAppIdData(appIdSession, ClientAppId, nullptr);
                    if (appIdSession->serviceAppId <= APP_ID_NONE)
                        seServiceAppIdData(appIdSession, serviceAppId, nullptr, nullptr);

                    // DO overwrite a previously-set data
                    setPayloadAppIdData(appIdSession, (ApplicationId)payloadAppId, nullptr);
                    setReferredPayloadAppIdData(appIdSession, referredPayloadAppId);
                }
            }

            if (thirdparty_appid_module)
            {
                thirdparty_appid_module->disable_flags(appIdSession->tpsession,
                    TP_SESSION_FLAG_ATTRIBUTE | TP_SESSION_FLAG_TUNNELING |
                    TP_SESSION_FLAG_FUTUREFLOW);
                thirdparty_appid_module->session_delete(appIdSession->tpsession, 1);
            }
            appIdSession->tpsession = nullptr;
            clearAppIdFlag(appIdSession, APPID_SESSION_APP_REINSPECT);
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_SSL, proto_list))
    {
        AppId tmpAppId = APP_ID_NONE;

        if (thirdparty_appid_module && appIdSession->tpsession)
            tmpAppId = thirdparty_appid_module->session_appid_get(appIdSession->tpsession);

        setAppIdFlag(appIdSession, APPID_SESSION_SSL_SESSION);

        if (!appIdSession->tsession)
            appIdSession->tsession = (tlsSession*)snort_calloc(sizeof(tlsSession));

        if (!appIdSession->ClientAppId)
            setClientAppIdData(appIdSession, APP_ID_SSL_CLIENT, nullptr);

        if (attribute_data->tlsHost)
        {
            if (appIdSession->tsession->tls_host)
                snort_free(appIdSession->tsession->tls_host);
            appIdSession->tsession->tls_host = attribute_data->tlsHost;
            attribute_data->tlsHost = nullptr;
            if (testSSLAppIdForReinspect(tmpAppId))
                appIdSession->scan_flags |= SCAN_SSL_HOST_FLAG;
        }
        if (testSSLAppIdForReinspect(tmpAppId))
        {
            if (attribute_data->tlsCname)
            {
                if (appIdSession->tsession->tls_cname)
                    snort_free(appIdSession->tsession->tls_cname);
                appIdSession->tsession->tls_cname = attribute_data->tlsCname;
                attribute_data->tlsCname = nullptr;
            }
            if (attribute_data->tlsOrgUnit)
            {
                if (appIdSession->tsession->tls_orgUnit)
                    snort_free(appIdSession->tsession->tls_orgUnit);
                appIdSession->tsession->tls_orgUnit = attribute_data->tlsOrgUnit;
                attribute_data->tlsOrgUnit = nullptr;
            }
        }
    }
    else if (ThirdPartyAppIDFoundProto(APP_ID_FTP_CONTROL, proto_list))
    {
        if (!pAppidActiveConfig->mod_config->ftp_userid_disabled && attribute_data->ftpCommandUser)
        {
            if (appIdSession->username)
                snort_free(appIdSession->username);
            appIdSession->username = attribute_data->ftpCommandUser;
            attribute_data->ftpCommandUser = nullptr;
            appIdSession->usernameService = APP_ID_FTP_CONTROL;
            setAppIdFlag(appIdSession, APPID_SESSION_LOGIN_SUCCEEDED);
        }
    }
}

void appSetServiceValidator(RNAServiceValidationFCN fcn, AppId appId, unsigned extractsInfo,
    AppIdConfig* pConfig)
{
    AppInfoTableEntry* pEntry = appInfoEntryGet(appId, pConfig);
    if (!pEntry)
    {
        ErrorMessage("AppId: invalid direct service AppId, %d", appId);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
    if (!extractsInfo)
    {
        DebugFormat(DEBUG_APPID, "Ignoring direct service without info for AppId %d", appId);
        return;
    }
    pEntry->svrValidator = ServiceGetServiceElement(fcn, nullptr, pConfig);
    if (pEntry->svrValidator)
        pEntry->flags |= extractsInfo;
    else
        ErrorMessage("AppId: failed to find a service element for AppId %d", appId);
}

void appSetLuaServiceValidator(RNAServiceValidationFCN fcn, AppId appId, unsigned extractsInfo,
    struct Detector* data)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;

    // FIXIT-L: what type of error would cause this lookup to fail? is this programming error
    // or user error due to misconfig or something like that... if change in handling needed
    // apply to all instances where this lookup is done
    if ((entry = appInfoEntryGet(appId, pConfig)))
    {
        entry->flags |= APPINFO_FLAG_ACTIVE;

        extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
        if (!extractsInfo)
        {
            DebugFormat(DEBUG_LOG, "Ignoring direct service without info for AppId: %d - %p\n",
                    appId, (void*)data);
            return;
        }

        entry->svrValidator = ServiceGetServiceElement(fcn, data, pConfig);
        if (entry->svrValidator)
            entry->flags |= extractsInfo;
        else
            ErrorMessage("AppId: Failed to find a service element for AppId: %d - %p\n",
                    appId, (void*)data);
    }
    else
    {
        ErrorMessage("Invalid direct service for AppId: %d - %p\n", appId, (void*)data);
    }
}

void appSetClientValidator(RNAClientAppFCN fcn, AppId appId, unsigned extractsInfo,
    AppIdConfig* pConfig)
{
    AppInfoTableEntry* pEntry = appInfoEntryGet(appId, pConfig);
    if (!pEntry)
    {
        ErrorMessage("AppId: invalid direct client application AppId: %d\n", appId);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
    if (!extractsInfo)
    {
        DebugFormat(DEBUG_LOG,
            "Ignoring direct client application without info for AppId: %d", appId);
        return;
    }
    pEntry->clntValidator = ClientAppGetClientAppModule(fcn, nullptr, &pConfig->clientAppConfig);
    if (pEntry->clntValidator)
        pEntry->flags |= extractsInfo;
    else
        ErrorMessage("Appid: Failed to find a client application module for AppId: %d\n", appId);
}

void appSetLuaClientValidator(RNAClientAppFCN fcn, AppId appId, unsigned extractsInfo, struct
    Detector* data)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if ((entry = appInfoEntryGet(appId, pConfig)))
    {
        entry->flags |= APPINFO_FLAG_ACTIVE;
        extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
        if (!extractsInfo)
        {
            DebugFormat(DEBUG_LOG,
                "Ignoring direct client application without info forAppId %d - %p\n",
                appId, (void*)data);
            return;
        }

        entry->clntValidator = ClientAppGetClientAppModule(fcn, data, &pConfig->clientAppConfig);
        if (entry->clntValidator)
            entry->flags |= extractsInfo;
        else
            ErrorMessage(
                "AppId: Failed to find a client application module forAppId: %d - %p\n",
                appId, (void*)data);
    }
    else
    {
        ErrorMessage("Invalid direct client application for AppId: %d - %p\n",
            appId, (void*)data);
        return;
    }
}

void AppIdAddUser(AppIdData* flowp, const char* username, AppId appId, int success)
{
    if (flowp->username)
        snort_free(flowp->username);
    flowp->username = snort_strdup(username);
    flowp->usernameService = appId;
    if (success)
        setAppIdFlag(flowp, APPID_SESSION_LOGIN_SUCCEEDED);
    else
        clearAppIdFlag(flowp, APPID_SESSION_LOGIN_SUCCEEDED);
}

void AppIdAddDnsQueryInfo(AppIdData* flow,
    uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset,
    uint16_t record_type)
{
    if ( flow->dsession )
    {
        if ( ( flow->dsession->state != 0 ) && ( flow->dsession->id != id ) )
            AppIdResetDnsInfo(flow);
    }
    else
        flow->dsession = (dnsSession*)snort_calloc(sizeof(dnsSession));

    if (flow->dsession->state & DNS_GOT_QUERY)
        return;
    flow->dsession->state |= DNS_GOT_QUERY;

    flow->dsession->id          = id;
    flow->dsession->record_type = record_type;

    if (!flow->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            flow->dsession->host_len    = host_len;
            flow->dsession->host_offset = host_offset;
            flow->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdAddDnsResponseInfo(AppIdData* flow,
    uint16_t id,
    const uint8_t* host, uint8_t host_len, uint16_t host_offset,
    uint8_t response_type, uint32_t ttl)
{
    if ( flow->dsession )
    {
        if ( ( flow->dsession->state != 0 ) && ( flow->dsession->id != id ) )
            AppIdResetDnsInfo(flow);
    }
    else
        flow->dsession = (dnsSession*)snort_calloc(sizeof(*flow->dsession));

    if (flow->dsession->state & DNS_GOT_RESPONSE)
        return;
    flow->dsession->state |= DNS_GOT_RESPONSE;

    flow->dsession->id            = id;
    flow->dsession->response_type = response_type;
    flow->dsession->ttl           = ttl;

    if (!flow->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            flow->dsession->host_len    = host_len;
            flow->dsession->host_offset = host_offset;
            flow->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

void AppIdResetDnsInfo(AppIdData* flow)
{
    if (flow->dsession)
    {
        snort_free(flow->dsession->host);
        memset(flow->dsession, 0, sizeof(*(flow->dsession)));
    }
}

void AppIdAddPayload(AppIdData* flow, AppId payload_id)
{
    if (pAppidActiveConfig->mod_config->instance_id)
        checkSandboxDetection(payload_id);
    flow->payloadAppId = payload_id;
}

AppId getOpenAppId(void* ssnptr)
{
    AppIdData* session;
    AppId payloadAppId = APP_ID_NONE;
    if (ssnptr && (session = getAppIdData(ssnptr)))
    {
        payloadAppId = session->payloadAppId;
    }

    return payloadAppId;
}

/**
 * @returns 1 if some appid is found, 0 otherwise.
 */
//int sslAppGroupIdLookup(void* ssnptr, const char* serverName, const char* commonName,
//    AppId* serviceAppId, AppId* ClientAppId, AppId* payloadAppId)
int sslAppGroupIdLookup(void*, const char*, const char*, AppId*, AppId*, AppId*)
{
#ifdef REMOVED_WHILE_NOT_IN_USE
    AppIdData* session;
    *serviceAppId = *ClientAppId = *payloadAppId = APP_ID_NONE;

    if (commonName)
    {
        ssl_scan_cname((const uint8_t*)commonName, strlen(commonName), ClientAppId, payloadAppId,
            &pAppidActiveConfig->serviceSslConfig);
    }
    if (serverName)
    {
        ssl_scan_hostname((const uint8_t*)serverName, strlen(serverName), ClientAppId,
            payloadAppId, &pAppidActiveConfig->serviceSslConfig);
    }

    if (ssnptr && (session = getAppIdData(ssnptr)))
    {
        *serviceAppId = pickServiceAppId(session);
        if (*ClientAppId == APP_ID_NONE)
        {
            *ClientAppId = pickClientAppId(session);
        }
        if (*payloadAppId == APP_ID_NONE)
        {
            *payloadAppId = pickPayloadId(session);
        }
    }
    if (*serviceAppId != APP_ID_NONE ||
        *ClientAppId != APP_ID_NONE ||
        *payloadAppId != APP_ID_NONE)
    {
        return 1;
    }
#endif

    return 0;
}

void httpHeaderCallback(Packet* p, HttpParsedHeaders* const headers)
{
    AppIdData* session;
    int direction;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (thirdparty_appid_module)
        return;
    if (!p || !(session = getAppIdData(p->flow)))
        return;

    direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if (!session->hsession)
        session->hsession = (decltype(session->hsession))snort_calloc(sizeof(httpSession));

    if (direction == APP_ID_FROM_INITIATOR)
    {
        if (headers->host.start)
        {
            snort_free(session->hsession->host);
            session->hsession->host = strndup((char*)headers->host.start, headers->host.len);
            session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;

            if (headers->url.start)
            {
                snort_free(session->hsession->url);
                session->hsession->url = (char*)snort_calloc(sizeof(HTTP_PREFIX) +
                    headers->host.len + headers->url.len);
                strcpy(session->hsession->url, HTTP_PREFIX);
                strncat(session->hsession->url, (char*)headers->host.start, headers->host.len);
                strncat(session->hsession->url, (char*)headers->url.start, headers->url.len);
                session->scan_flags |= SCAN_HTTP_HOST_URL_FLAG;
            }
        }
        if (headers->userAgent.start)
        {
            snort_free(session->hsession->useragent);
            session->hsession->useragent  = strndup((char*)headers->userAgent.start,
                headers->userAgent.len);
            session->scan_flags |= SCAN_HTTP_USER_AGENT_FLAG;
        }
        if (headers->referer.start)
        {
            snort_free(session->hsession->referer);
            session->hsession->referer  = strndup((char*)headers->referer.start,
                headers->referer.len);
        }
        if (headers->via.start)
        {
            snort_free(session->hsession->via);
            session->hsession->via  = strndup((char*)headers->via.start, headers->via.len);
            session->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
    }
    else
    {
        if (headers->via.start)
        {
            snort_free(session->hsession->via);
            session->hsession->via  = strndup((char*)headers->via.start, headers->via.len);
            session->scan_flags |= SCAN_HTTP_VIA_FLAG;
        }
        if (headers->contentType.start)
        {
            snort_free(session->hsession->content_type);
            session->hsession->content_type  = strndup((char*)headers->contentType.start,
                headers->contentType.len);
        }
        if (headers->responseCode.start)
        {
            long responseCodeNum;
            responseCodeNum = strtoul((char*)headers->responseCode.start, nullptr, 10);
            if (responseCodeNum > 0 && responseCodeNum < 700)
            {
                snort_free(session->hsession->response_code);
                session->hsession->response_code  = strndup((char*)headers->responseCode.start,
                    headers->responseCode.len);
            }
        }
    }
    processHTTPPacket(p, session, direction, headers, pConfig);

    setAppIdFlag(session, APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_HTTP_SESSION);

// FIXIT-M:
#ifdef REMOVED_WHILE_NOT_IN_USE
    _dpd.streamAPI->set_application_id(p->flow, pickServiceAppId(session),
        pickClientAppId(session), pickPayloadId(session), pickMiscAppId(session));
#endif
}

static inline void ExamineRtmpMetadata(AppIdData* appIdSession)
{
    AppId serviceAppId = 0;
    AppId ClientAppId = 0;
    AppId payloadAppId = 0;
    AppId referredPayloadAppId = 0;
    char* version = nullptr;
    httpSession* hsession;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (!appIdSession->hsession)
        appIdSession->hsession = (httpSession*)snort_calloc(sizeof(httpSession));

    hsession = appIdSession->hsession;

    if (hsession->url)
    {
        if (((getAppIdFromUrl(nullptr, hsession->url, &version,
            hsession->referer, &ClientAppId, &serviceAppId,
            &payloadAppId, &referredPayloadAppId, 1, &pConfig->detectorHttpConfig)) ||
            (getAppIdFromUrl(nullptr, hsession->url, &version,
            hsession->referer, &ClientAppId, &serviceAppId,
            &payloadAppId, &referredPayloadAppId, 0, &pConfig->detectorHttpConfig))) == 1)
        {
            /* do not overwrite a previously-set client or service */
            if (appIdSession->ClientAppId <= APP_ID_NONE)
                setClientAppIdData(appIdSession, ClientAppId, nullptr);
            if (appIdSession->serviceAppId <= APP_ID_NONE)
                seServiceAppIdData(appIdSession, serviceAppId, nullptr, nullptr);

            /* DO overwrite a previously-set data */
            setPayloadAppIdData(appIdSession, (ApplicationId)payloadAppId, nullptr);
            setReferredPayloadAppIdData(appIdSession, referredPayloadAppId);
        }
    }
}

void checkSandboxDetection(AppId appId)
{
    AppInfoTableEntry* entry;
    AppIdConfig* pConfig = pAppidActiveConfig;

    if (pAppidActiveConfig->mod_config->instance_id && pConfig)
    {
        entry = appInfoEntryGet(appId, pConfig);
        if (entry && entry->flags & APPINFO_FLAG_ACTIVE)
        {
            fprintf(SF_DEBUG_FILE, "add service\n");
            fprintf(SF_DEBUG_FILE, "Detected AppId %d\n", entry->appId);
        }
    }
}

