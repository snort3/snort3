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

// service_base.cc author Ron Dempster <Ron.Dempster@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_base.h"

#include <algorithm>

#include "log/messages.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "search_engines/search_tool.h"

#include "app_info_table.h"
#include "appid_config.h"
#include "appid_utils/ip_funcs.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_sip.h"
#include "lua_detector_api.h"

#include "service_api.h"
#include "service_battle_field.h"
#include "service_bgp.h"
#include "service_bootp.h"
#include "service_dcerpc.h"
#include "service_direct_connect.h"
#include "service_flap.h"
#include "service_ftp.h"
#include "service_irc.h"
#include "service_lpr.h"
#include "service_mdns.h"
#include "service_mysql.h"
#include "service_netbios.h"
#include "service_nntp.h"
#include "service_ntp.h"
#include "service_radius.h"
#include "service_rexec.h"
#include "service_rfb.h"
#include "service_rlogin.h"
#include "service_rpc.h"
#include "service_rshell.h"
#include "service_rsync.h"
#include "service_rtmp.h"
#include "service_snmp.h"
#include "service_ssh.h"
#include "service_ssl.h"
#include "service_telnet.h"
#include "service_tftp.h"

//#define SERVICE_DEBUG 1
//#define SERVICE_DEBUG_PORT  80

#ifdef SERVICE_DEBUG
static const char* service_id_state_name[] =
{
    "NEW",
    "VALID",
    "PORT",
    "PATTERN",
    "BRUTE_FORCE"
};

#ifdef SERVICE_DEBUG_PORT
#define APPID_LOG_SERVICE(fmt) fprintf(SF_DEBUG_FILE, fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...) \
        if (dp == SERVICE_DEBUG_PORT || sp == SERVICE_DEBUG_PORT) \
            fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) \
        if (port == SERVICE_DEBUG_PORT) \
            fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) \
        if (dp == SERVICE_DEBUG_PORT || sp == SERVICE_DEBUG_PORT) \
        { \
            char ipstr[INET6_ADDRSTRLEN]; \
            sfip_ntop(&ip, ipstr, sizeof(ipstr)); \
            fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__); \
        }
#else
#define APPID_LOG_SERVICE(fmt) fprintf(SF_DEBUG_FILE, fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...) fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) \
    UNUSED(port); \
    fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__)
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) \
        { \
            char ipstr[INET6_ADDRSTRLEN]; \
            sfip_ntop(&ip, ipstr, sizeof(ipstr)); \
            fprintf(SF_DEBUG_FILE, fmt, __VA_ARGS__); \
        }
#endif
#else
#define APPID_LOG_SERVICE(fmt)
#define APPID_LOG_FILTER_PORTS(dp, sp, fmt, ...)
#define APPID_LOG_FILTER_SERVICE_PORT(port, fmt, ...) UNUSED(port);
#define APPID_LOG_IP_FILTER_PORTS(dp, sp, ip, fmt, ...) UNUSED(ip);
#endif

#define BUFSIZE         512

#define STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT 3
#define STATE_ID_INVALID_CLIENT_THRESHOLD    9
#define STATE_ID_MAX_VALID_COUNT             5
#define STATE_ID_NEEDED_DUPE_DETRACT_COUNT   3

/* If this is greater than 1, more than 1 service detector can be searched for
 * and tried per flow based on port/pattern (if a valid detector doesn't
 * already exist). */
#define MAX_CANDIDATE_SERVICES 10
#define DHCP_OPTION55_LEN_MAX 255

#define FINGERPRINT_UDP_FLAGS_XENIX 0x00000800
#define FINGERPRINT_UDP_FLAGS_NT    0x00001000
#define FINGERPRINT_UDP_FLAGS_MASK  (FINGERPRINT_UDP_FLAGS_XENIX | FINGERPRINT_UDP_FLAGS_NT)

static void* service_flowdata_get(AppIdSession* asd, unsigned service_id);
static int service_flowdata_add(AppIdSession* asd, void* data, unsigned service_id, AppIdFreeFCN
    fcn);
static void add_host_info(AppIdSession* asd, SERVICE_HOST_INFO_CODE code, const void* info);
static int add_dhcp_info(AppIdSession* asd, unsigned op55_len, const uint8_t* op55, unsigned
    op60_len, const uint8_t* op60, const uint8_t* mac);
static void add_host_ip_info(AppIdSession* asd, const uint8_t* mac, uint32_t ip4,
    int32_t zone, uint32_t subnetmask, uint32_t leaseSecs, uint32_t router);
static void add_smb_info(AppIdSession* asd, unsigned major, unsigned minor, uint32_t flags);
static void add_miscellaneous_info(AppIdSession* asd, AppId miscId);
static void add_dns_query_info(AppIdSession*, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint16_t record_type);
static void add_dns_response_info(AppIdSession*, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint8_t response_type, uint32_t ttl);
static void reset_dns_info(AppIdSession*);

static const uint8_t zeromac[6] = { 0, 0, 0, 0, 0, 0 };
static THREAD_LOCAL DHCPInfo* dhcp_info_free_list = nullptr;
static THREAD_LOCAL FpSMBData* smb_data_free_list = nullptr;
static THREAD_LOCAL ServiceConfig* service_config = nullptr;
static THREAD_LOCAL RNAServiceElement* ftp_service = nullptr;
static THREAD_LOCAL ServicePatternData* free_pattern_data = nullptr;

const ServiceApi serviceapi =
{
    &service_flowdata_get,
    &service_flowdata_add,
    &add_dhcp_info,
    &add_host_ip_info,
    &add_smb_info,
    &AppIdServiceAddService,
    &AppIdServiceFailService,
    &AppIdServiceInProcess,
    &AppIdServiceIncompatibleData,
    &add_host_info,
    &AppIdSession::add_payload,
    &AppIdSession::add_user,
    &AppIdServiceAddServiceSubtype,
    &add_miscellaneous_info,
    &add_dns_query_info,
    &add_dns_response_info,
    &reset_dns_info,
};

/*C service API */
static void ServiceRegisterPattern(RNAServiceValidationFCN, IpProtocol, const uint8_t*, unsigned,
    int, Detector*, int, const char* );
static void CServiceRegisterPattern(RNAServiceValidationFCN, IpProtocol, const uint8_t*, unsigned,
    int, const char*);
static void ServiceRegisterPatternUser(RNAServiceValidationFCN, IpProtocol, const uint8_t*,
    unsigned, int, const char*);
static void appSetServiceValidator( RNAServiceValidationFCN, AppId, unsigned extractsInfo);
static int CServiceAddPort(const RNAServiceValidationPort*, RNAServiceValidationModule*);
static void CServiceRemovePorts(RNAServiceValidationFCN validate);

static InitServiceAPI svc_init_api =
{
    &CServiceRegisterPattern,
    &CServiceAddPort,
    &CServiceRemovePorts,
    &ServiceRegisterPatternUser,
    &appSetServiceValidator,
    0,
    0,
    nullptr
};

extern RNAServiceValidationModule timbuktu_service_mod;
extern RNAServiceValidationModule bit_service_mod;
extern RNAServiceValidationModule tns_service_mod;
extern RNAServiceValidationModule http_service_mod;

static RNAServiceValidationModule* static_service_list[] =
{
    &bgp_service_mod,
    &bootp_service_mod,
    &dcerpc_service_mod,
    &dns_service_mod,
    &flap_service_mod,
    &ftp_service_mod,
    &irc_service_mod,
    &lpr_service_mod,
    &mysql_service_mod,
    &netbios_service_mod,
    &nntp_service_mod,
    &ntp_service_mod,
    &radius_service_mod,
    &rexec_service_mod,
    &rfb_service_mod,
    &rlogin_service_mod,
    &rpc_service_mod,
    &rshell_service_mod,
    &rsync_service_mod,
    &rtmp_service_mod,
    &snmp_service_mod,
    &ssh_service_mod,
    &ssl_service_mod,
    &telnet_service_mod,
    &tftp_service_mod,
    &sip_service_mod,
    &directconnect_service_mod,
    &battlefield_service_mod,
    &mdns_service_mod,
    &timbuktu_service_mod,
    &tns_service_mod,
    &bit_service_mod,
    &pattern_service_mod,
    &http_service_mod
};

const uint32_t NUM_STATIC_SERVICES =
        sizeof(static_service_list) / sizeof(RNAServiceValidationModule*);

static void appSetServiceValidator(RNAServiceValidationFCN fcn, AppId appId, unsigned extractsInfo)
{
    AppInfoTableEntry* pEntry = AppInfoManager::get_instance().get_app_info_entry(appId);
    if (!pEntry)
    {
        ParseWarning(WARN_RULES,
          "AppId: ID to Name mapping entry missing for AppId: %d. No rule support for this ID.",
          appId);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_SERVICE_ADDITIONAL | APPINFO_FLAG_SERVICE_UDP_REVERSED);
    if (!extractsInfo)
    {
        DebugFormat(DEBUG_APPID, "Ignoring direct service without info for AppId %d", appId);
        return;
    }
    pEntry->svrValidator = get_service_element(fcn, nullptr);
    if (pEntry->svrValidator)
        pEntry->flags |= extractsInfo;
    else
        ErrorMessage("AppId: failed to find a service element for AppId %d", appId);
}


int AddFTPServiceState(AppIdSession* asd)
{
    if (!ftp_service)
        return -1;
    return asd->add_flow_data_id(21, ftp_service);
}

static inline ServiceMatch* allocServiceMatch(void)
{
    return (ServiceMatch*)snort_calloc(sizeof(ServiceMatch));
}

static int pattern_match(void* id, void*, int index, void* data, void*)
{
    ServiceMatch** matches = (ServiceMatch**)data;
    ServicePatternData* pd = (ServicePatternData*)id;
    ServiceMatch* sm;

    if (pd->position >= 0 && pd->position != index)
        return 0;

    for (sm = *matches; sm; sm = sm->next)
        if (sm->svc == pd->svc)
            break;

    if (sm)
        sm->count++;
    else
    {
        sm = allocServiceMatch();
        sm->count++;
        sm->svc = pd->svc;
        sm->size = pd->size;
        sm->next = *matches;
        *matches = sm;
    }
    return 0;
}

AppId getPortServiceId(IpProtocol proto, uint16_t port, const AppIdConfig* config)
{
    AppId appId;

    if (proto == IpProtocol::TCP)
        appId = config->tcp_port_only[port];
    else if (proto == IpProtocol::UDP)
        appId = config->udp_port_only[port];
    else
        appId = config->ip_protocol[(uint16_t)proto];

    return appId;
}

static inline uint16_t sslPortRemap(uint16_t port)
{
    switch (port)
    {
    case 465:
        return 25;
    case 563:
        return 119;
    case 585:
    case 993:
        return 143;
    case 990:
        return 21;
    case 992:
        return 23;
    case 994:
        return 6667;
    case 995:
        return 110;
    default:
        return 0;
    }
}

static inline RNAServiceElement* AppIdGetNexServiceByPort( IpProtocol protocol, uint16_t port,
    const RNAServiceElement* const lasService, AppIdSession* asd)
{
    RNAServiceElement* service = nullptr;
    SF_LIST* list = nullptr;

    if (get_service_detect_level(asd) == 1)
    {
        unsigned remappedPort = sslPortRemap(port);
        if (remappedPort)
            list = service_config->tcp_services[remappedPort];
    }
    else if (protocol == IpProtocol::TCP)
        list = service_config->tcp_services[port];
    else
        list = service_config->udp_services[port];

    if (list)
    {
        SF_LNODE* iter = nullptr;

        service = (RNAServiceElement*)sflist_first(list, &iter);
        if (lasService)
        {
            while ( service && ((service->validate != lasService->validate) ||
                (service->userdata != lasService->userdata)))
                service = (RNAServiceElement*)sflist_next(&iter);
            if (service)
                service = (RNAServiceElement*)sflist_next(&iter);
        }
    }

    APPID_LOG_FILTER_SERVICE_PORT(port, "Port service for protocol %u port %u, service %s\n",
        (unsigned)protocol, (unsigned)port, (service && service->name) ? service->name :
        "UNKNOWN");

    return service;
}

static inline RNAServiceElement* get_service_by_pattern(AppIdServiceIDState* id_state,
        uint16_t port)
{
    RNAServiceElement* service = nullptr;

    while (id_state->current_service)
    {
        id_state->current_service = id_state->current_service->next;
        if (id_state->current_service && id_state->current_service->svc->current_ref_count)
        {
            service = id_state->current_service->svc;
            break;
        }
    }

    APPID_LOG_FILTER_SERVICE_PORT(port, "Next pattern service %s\n",
        (service && service->name) ? service->name : "UNKNOWN");

    return service;
}

const RNAServiceElement* get_service_element(RNAServiceValidationFCN fcn, Detector* userdata)
{
    RNAServiceElement* li;

    for (li = service_config->tcp_service_list; li; li = li->next)
        if ((li->validate == fcn) && (li->userdata == userdata))
            return li;

    for (li = service_config->udp_service_list; li; li = li->next)
        if ((li->validate == fcn) && (li->userdata == userdata))
            return li;

    return nullptr;
}

static void ServiceRegisterPattern(RNAServiceValidationFCN fcn, IpProtocol proto,
        const uint8_t* pattern, unsigned size, int position, Detector* userdata,
        int provides_user, const char* name)
{
    SearchTool** patterns;
    ServicePatternData** pd_list;
    int* count;
    ServicePatternData* pd;
    RNAServiceElement** list;
    RNAServiceElement* li;

    if ((IpProtocol)proto == IpProtocol::TCP)
    {
        patterns = &service_config->tcp_patterns;
        pd_list = &service_config->tcp_pattern_data;

        count = &service_config->tcp_pattern_count;
        list = &service_config->tcp_service_list;
    }
    else if ((IpProtocol)proto == IpProtocol::UDP)
    {
        patterns = &service_config->udp_patterns;
        pd_list = &service_config->udp_pattern_data;

        count = &service_config->udp_pattern_count;
        list = &service_config->udp_service_list;
    }
    else
    {
        ErrorMessage("Invalid protocol when registering a pattern: %u\n",(unsigned)proto);
        return;
    }

    for (li = *list; li; li=li->next)
    {
        if ((li->validate == fcn) && (li->userdata == userdata))
            break;
    }
    if (!li)
    {
        li = new RNAServiceElement;
        li->init(name, fcn, userdata, provides_user, DETECTOR_TYPE_PATTERN);
        li->next = *list;
        *list = li;
    }

    if ( !(*patterns) )
    {
        *patterns = new SearchTool("ac_full");
        if (!(*patterns))
        {
            ErrorMessage("Error initializing the pattern table for protocol %u\n",(unsigned)proto);
            return;
        }
    }

    if (free_pattern_data)
    {
        pd = free_pattern_data;
        free_pattern_data = pd->next;
        memset(pd, 0, sizeof(*pd));
    }
    else
        pd = (ServicePatternData*)snort_calloc(sizeof(ServicePatternData));

    pd->svc = li;
    pd->size = size;
    pd->position = position;
    (*patterns)->add(pattern, size, pd, false);
    (*count)++;
    pd->next = *pd_list;
    *pd_list = pd;
    li->ref_count++;
}

void ServiceRegisterPatternDetector(RNAServiceValidationFCN fcn,
    IpProtocol proto, const uint8_t* pattern, unsigned size,
    int position, Detector* userdata, const char* name)
{
    ServiceRegisterPattern(fcn, proto, pattern, size, position, userdata, 0, name);
}

static void ServiceRegisterPatternUser(RNAServiceValidationFCN fcn, IpProtocol proto,
    const uint8_t* pattern, unsigned size, int position, const char* name)
{
    ServiceRegisterPattern(fcn, proto, pattern, size, position, nullptr, 1, name);
}

static void CServiceRegisterPattern(RNAServiceValidationFCN fcn, IpProtocol proto,
    const uint8_t* pattern, unsigned size, int position, const char* name)
{
    ServiceRegisterPattern(fcn, proto, pattern, size, position, nullptr, 0, name);
}

static void RemoveServicePortsByType(RNAServiceValidationFCN validate, SF_LIST** services,
    RNAServiceElement* list, Detector* userdata)
{
    RNAServiceElement* li;
    unsigned i;

    for (li = list; li; li=li->next)
    {
        if (li->validate == validate && li->userdata == userdata)
            break;
    }
    if (li == nullptr)
        return;

    for (i=0; i < RNA_SERVICE_MAX_PORT; i++)
    {
        SF_LIST* listTmp;

        if ( ( listTmp = services[i] ) )
        {
            SF_LNODE* iter;
            RNAServiceElement* liTmp;

            liTmp = (RNAServiceElement*)sflist_first(listTmp, &iter);
            while (liTmp)
            {
                if (liTmp == li)
                {
                    li->ref_count--;
                    sflist_remove_node(listTmp, iter);
                    // FIXIT-M Revisit this for better solution to calling sflist_first after
                    // deleting a node... ultimate solution for use of sflist would be move
                    // to STL
                    liTmp = (RNAServiceElement*)sflist_first(listTmp, &iter);
                }
                else
                    liTmp = (RNAServiceElement*)sflist_next(&iter);
            }
        }
    }
}

static void RemoveAllServicePorts()
{
    for (unsigned i = 0; i < RNA_SERVICE_MAX_PORT; i++)
    {
        if (service_config->tcp_services[i])
        {
            sflist_free(service_config->tcp_services[i]);
            service_config->tcp_services[i] = nullptr;
        }
    }
    for (unsigned i = 0; i < RNA_SERVICE_MAX_PORT; i++)
    {
        if (service_config->udp_services[i])
        {
            sflist_free(service_config->udp_services[i]);
            service_config->udp_services[i] = nullptr;
        }
    }
    for (unsigned i = 0; i < RNA_SERVICE_MAX_PORT; i++)
    {
        if (service_config->udp_reversed_services[i])
        {
            sflist_free(service_config->udp_reversed_services[i]);
            service_config->udp_reversed_services[i] = nullptr;
        }
    }
}

void ServiceRemovePorts(RNAServiceValidationFCN validate, Detector* userdata)
{
    RemoveServicePortsByType(validate, service_config->tcp_services,
        service_config->tcp_service_list, userdata);
    RemoveServicePortsByType(validate, service_config->udp_services,
        service_config->udp_service_list, userdata);
    RemoveServicePortsByType(validate, service_config->udp_reversed_services,
        service_config->udp_reversed_service_list, userdata);
}

static void CServiceRemovePorts(RNAServiceValidationFCN validate)
{
    ServiceRemovePorts(validate, nullptr);
}

int ServiceAddPort(const RNAServiceValidationPort* pp, RNAServiceValidationModule* svm,
    Detector* userdata)
{
    SF_LIST** services;
    RNAServiceElement** list = nullptr;
    RNAServiceElement* li;
    RNAServiceElement* serviceElement;

    DebugFormat(DEBUG_APPID, "Adding service %s for protocol %u on port %u\n",
        svm->name, (unsigned)pp->proto, (unsigned)pp->port);
    if (pp->proto == IpProtocol::TCP)
    {
        services = service_config->tcp_services;
        list = &service_config->tcp_service_list;
    }
    else if (pp->proto == IpProtocol::UDP)
    {
        if (!pp->reversed_validation)
        {
            services = service_config->udp_services;
            list = &service_config->udp_service_list;
        }
        else
        {
            services = service_config->udp_reversed_services;
            list = &service_config->udp_reversed_service_list;
        }
    }
    else
    {
        ErrorMessage("Service %s did not have a valid protocol (%u)\n",
            svm->name, (unsigned)pp->proto);
        return 0;
    }

    for (li = *list; li; li = li->next)
    {
        if (li->validate == pp->validate && li->userdata == userdata)
            break;
    }
    if (!li)
    {
        li = new RNAServiceElement;
        li->init(svm->name, pp->validate, userdata, svm->provides_user, DETECTOR_TYPE_PORT);
        li->next = *list;
        *list = li;
    }

    if (pp->proto == IpProtocol::TCP && pp->port == 21 && !ftp_service)
    {
        ftp_service = li;
        li->ref_count++;
    }

    /*allocate a new list if this is first detector for this port. */
    if (!services[pp->port])
    {
        services[pp->port] = (SF_LIST*)snort_alloc(sizeof(SF_LIST));
        sflist_init(services[pp->port]);
    }

    /*search and add if not present. */
    SF_LNODE* iter = nullptr;
    for (serviceElement = (RNAServiceElement*)sflist_first(services[pp->port], &iter);
        serviceElement && (serviceElement != li);
        serviceElement = (RNAServiceElement*)sflist_next(&iter))
        ;

    if (!serviceElement)
        sflist_add_tail(services[pp->port], li);

    li->ref_count++;
    return 0;
}

static int CServiceAddPort(const RNAServiceValidationPort* pp, RNAServiceValidationModule* svm)
{
    return ServiceAddPort(pp, svm, nullptr);
}

void add_service_to_active_list(RNAServiceValidationModule* service)
{
    service->next = service_config->active_service_list;
    service_config->active_service_list = service;
}

static int serviceLoadForConfigCallback(void* symbol)
{
    static unsigned service_module_index = 0;
    RNAServiceValidationModule* svm = (RNAServiceValidationModule*)symbol;
    const RNAServiceValidationPort* pp;

    if (service_module_index >= 65536)
    {
        ErrorMessage("Maximum number of service modules exceeded");
        return -1;
    }

    svm->api = &serviceapi;
    for (pp = svm->pp; pp && pp->validate; pp++)
        if (CServiceAddPort(pp, svm))
            return -1;

    if (svm->init(&svc_init_api))
        ErrorMessage("Error initializing service %s\n",svm->name);

    svm->next = service_config->active_service_list;
    service_config->active_service_list = svm;

    svm->flow_data_index = service_module_index | APPID_SESSION_DATA_SERVICE_MODSTATE_BIT;
    service_module_index++;

    return 0;
}

int serviceLoadCallback(void* symbol)
{
    return serviceLoadForConfigCallback(symbol);
}

static int load_service_detectors()
{
    svc_init_api.instance_id = AppIdConfig::get_appid_config()->mod_config->instance_id;
    svc_init_api.debug = AppIdConfig::get_appid_config()->mod_config->debug;
    svc_init_api.pAppidConfig = AppIdConfig::get_appid_config();

    for ( unsigned i = 0; i < NUM_STATIC_SERVICES; i++)
    {
        if (serviceLoadForConfigCallback(static_service_list[i]))
            return -1;
    }

    return 0;
}

void init_service_plugins()
{
    service_config = new ServiceConfig;

    if ( load_service_detectors() )
        exit(-1);
}

void finalize_service_patterns()
{
    ServicePatternData* lists[] = { service_config->tcp_pattern_data,
                                    service_config->udp_pattern_data };

    for ( unsigned i = 0; i < (sizeof(lists) / sizeof(*lists)); i++)
    {
        ServicePatternData* curr = lists[i];
        while (curr != nullptr)
        {
            if (curr->svc != nullptr)
            {
                bool isActive = true;
                if (curr->svc->userdata && !curr->svc->userdata->isActive)
                {
                    /* C detectors don't have userdata here, but they're always
                     * active.  So, this check is really just for Lua
                     * detectors. */
                    isActive = false;
                }
                if (isActive)
                {
                    curr->svc->current_ref_count = curr->svc->ref_count;
                }
            }
            curr = curr->next;
        }
    }

    if (service_config->tcp_patterns)
        service_config->tcp_patterns->prep();
    if (service_config->udp_patterns)
        service_config->udp_patterns->prep();
}

void clean_service_plugins()
{
    ServicePatternData* pattern;
    RNAServiceElement* se;
    RNAServiceValidationModule* svm;
    FpSMBData* sd;
    DHCPInfo* info;

    if (!service_config)
        return;

    if (service_config->tcp_patterns)
    {
        delete service_config->tcp_patterns;
        service_config->tcp_patterns = nullptr;
    }

    if (service_config->udp_patterns)
    {
        delete service_config->udp_patterns;
        service_config->udp_patterns = nullptr;
    }

    while ((pattern = service_config->tcp_pattern_data))
    {
        service_config->tcp_pattern_data = pattern->next;
        snort_free(pattern);
    }

    while ((pattern = service_config->udp_pattern_data))
    {
        service_config->udp_pattern_data = pattern->next;
        snort_free(pattern);
    }

    while ((pattern = free_pattern_data))
    {
        free_pattern_data = pattern->next;
        snort_free(pattern);
    }

    while ((se = service_config->tcp_service_list))
    {
        service_config->tcp_service_list = se->next;
        delete se;
    }

    while ((se = service_config->udp_service_list))
    {
        service_config->udp_service_list = se->next;
        delete se;
    }

    while ((se = service_config->udp_reversed_service_list))
    {
        service_config->udp_reversed_service_list = se->next;
        delete se;
    }

    while ((sd = smb_data_free_list))
    {
        smb_data_free_list = sd->next;
        snort_free(sd);
    }

    while ((info = dhcp_info_free_list))
    {
        dhcp_info_free_list = info->next;
        snort_free(info);
    }

    RemoveAllServicePorts();

    for (svm = service_config->active_service_list; svm; svm = svm->next)
    {
        if (svm->clean)
            svm->clean();
    }

    clean_service_port_patterns();

    delete service_config;
    service_config = nullptr;
}

static int AppIdPatternPrecedence(const void* a, const void* b)
{
    const ServiceMatch* sm1 = (ServiceMatch*)a;
    const ServiceMatch* sm2 = (ServiceMatch*)b;

    /*higher precedence should be before lower precedence */
    if (sm1->count != sm2->count)
        return (sm2->count - sm1->count);
    else
        return (sm2->size - sm1->size);
}

void free_service_match_list(ServiceMatch* sm)
{
    ServiceMatch* tmpSm;

    while( sm )
    {
        tmpSm = sm;
        sm = sm->next;
        snort_free(tmpSm);
    }
}

/**Perform pattern match of a packet and construct a list of services sorted in order of
 * precedence criteria. Criteria is count and then size. The first service in the list is
 * returned. The list itself is saved in AppIdServiceIDState. If
 * appId is already identified, then use it instead of searching again. RNA will capability
 * to try out other inferior matches. If appId is unknown i.e. searched and not found by FRE then
 * dont do any pattern match. This is a way degrades RNA detector selection if FRE is running on
 * this sensor.
*/
static inline RNAServiceElement* AppIdGetServiceByPattern(const Packet* pkt, IpProtocol proto,
    const int, AppIdServiceIDState* id_state)
{
    SearchTool* patterns = nullptr;
    std::vector<ServiceMatch*> smOrderedList;

    if (proto == IpProtocol::TCP)
        patterns = service_config->tcp_patterns;
    else
        patterns = service_config->udp_patterns;

    if (!patterns)
    {
        APPID_LOG_SERVICE("Pattern bailing due to no patterns\n");
        return nullptr;
    }

    /*FRE didn't search */
    ServiceMatch* match_list = nullptr;
    patterns->find_all((char*)pkt->data, pkt->dsize, &pattern_match, false, (void*)&match_list);

    for (ServiceMatch* sm = match_list; sm; sm = sm->next)
        smOrderedList.push_back(sm);

    if (smOrderedList.size() == 0)
        return nullptr;

    std::sort(smOrderedList.begin(), smOrderedList.end(), AppIdPatternPrecedence);

    unsigned i;
    for (i = 0; i < smOrderedList.size() - 1; i++)
        smOrderedList[i]->next = smOrderedList[i + 1];
    smOrderedList[i]->next = nullptr;

    RNAServiceElement* service = smOrderedList[0]->svc;

    if (id_state)
    {
        id_state->svc = service;
        id_state->free_service_match_list();
        id_state->service_list = smOrderedList[0];
        id_state->current_service = smOrderedList[0];
    }
    else
        free_service_match_list(smOrderedList[0]);

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "Pattern service for protocol %u (%u->%u), %s\n",
        (unsigned)proto, (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp,
        (service && service->name) ? service->name : "UNKNOWN");
    return service;
}

static inline RNAServiceElement* AppIdGetServiceByBruteForce(IpProtocol protocol,
    const RNAServiceElement* lasService)
{
    RNAServiceElement* service = nullptr;

    if (lasService)
        service = lasService->next;
    else
        service = ((protocol == IpProtocol::TCP) ? service_config->tcp_service_list :
            service_config->udp_service_list);

    while (service && !service->current_ref_count)
        service = service->next;

    return service;
}

static void add_host_info(AppIdSession*, SERVICE_HOST_INFO_CODE, const void*)
{
}

void AppIdFreeDhcpData(DHCPData* dd)
{
    snort_free(dd);
}

static int add_dhcp_info(AppIdSession* asd, unsigned op55_len, const uint8_t* op55, unsigned
    op60_len, const uint8_t* op60, const uint8_t* mac)
{
    if (op55_len && op55_len <= DHCP_OPTION55_LEN_MAX
            && !asd->get_session_flags(APPID_SESSION_HAS_DHCP_FP))
    {
        DHCPData* rdd = (DHCPData*)snort_calloc(sizeof(*rdd));
        if (asd->add_flow_data(rdd, APPID_SESSION_DATA_DHCP_FP_DATA,
            (AppIdFreeFCN)AppIdFreeDhcpData))
        {
            AppIdFreeDhcpData(rdd);
            return -1;
        }

        asd->set_session_flags(APPID_SESSION_HAS_DHCP_FP);
        rdd->op55_len = (op55_len > DHCP_OP55_MAX_SIZE) ? DHCP_OP55_MAX_SIZE : op55_len;
        memcpy(rdd->op55, op55, rdd->op55_len);
        rdd->op60_len =  (op60_len > DHCP_OP60_MAX_SIZE) ? DHCP_OP60_MAX_SIZE : op60_len;
        if (op60_len)
            memcpy(rdd->op60, op60, rdd->op60_len);
        memcpy(rdd->eth_addr, mac, sizeof(rdd->eth_addr));
    }
    return 0;
}

void AppIdFreeDhcpInfo(DHCPInfo* dd)
{
    if (dd)
    {
        dd->next = dhcp_info_free_list;
        dhcp_info_free_list = dd;
    }
}

static unsigned isIPv4HostMonitored(uint32_t ip4, int32_t zone)
{
    NetworkSet* net_list;
    unsigned flags;
    AppIdConfig* config = AppIdConfig::get_appid_config();

    if (zone >= 0 && zone < MAX_ZONES && config->net_list_by_zone[zone])
        net_list = config->net_list_by_zone[zone];
    else
        net_list = config->net_list;

    NetworkSetManager::contains_ex(net_list, ip4, &flags);
    return flags;
}

static void add_host_ip_info(AppIdSession* asd, const uint8_t* mac, uint32_t ip, int32_t zone,
    uint32_t subnetmask, uint32_t leaseSecs, uint32_t router)
{
    DHCPInfo* info;

    if (memcmp(mac, zeromac, 6) == 0 || ip == 0)
        return;

    if (!asd->get_session_flags(APPID_SESSION_DO_RNA)
            || asd->get_session_flags(APPID_SESSION_HAS_DHCP_INFO))
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

    if (asd->add_flow_data(info, APPID_SESSION_DATA_DHCP_INFO,
        (AppIdFreeFCN)AppIdFreeDhcpInfo))
    {
        AppIdFreeDhcpInfo(info);
        return;
    }
    asd->set_session_flags(APPID_SESSION_HAS_DHCP_INFO);
    info->ipAddr = ip;
    memcpy(info->eth_addr, mac, sizeof(info->eth_addr));
    info->subnetmask = subnetmask;
    info->leaseSecs = leaseSecs;
    info->router = router;
}

void AppIdFreeSMBData(FpSMBData* sd)
{
    if (sd)
    {
        sd->next = smb_data_free_list;
        smb_data_free_list = sd;
    }
}

static void add_smb_info(AppIdSession* asd, unsigned major, unsigned minor, uint32_t flags)
{
    FpSMBData* sd;

    if (flags & FINGERPRINT_UDP_FLAGS_XENIX)
        return;

    if (smb_data_free_list)
    {
        sd = smb_data_free_list;
        smb_data_free_list = sd->next;
    }
    else
        sd = (FpSMBData*)snort_calloc(sizeof(FpSMBData));

    if (asd->add_flow_data(sd, APPID_SESSION_DATA_SMB_DATA, (AppIdFreeFCN)AppIdFreeSMBData))
    {
        AppIdFreeSMBData(sd);
        return;
    }

    asd->set_session_flags(APPID_SESSION_HAS_SMB_INFO);
    sd->major = major;
    sd->minor = minor;
    sd->flags = flags & FINGERPRINT_UDP_FLAGS_MASK;
}

static int AppIdServiceAddServiceEx(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, AppId appId, const char* vendor, const char* version)
{
    AppIdServiceIDState* id_state = nullptr;
    uint16_t port = 0;
    const SfIp* ip = nullptr;

    if ( !pkt || !svc_element )
    {
        ErrorMessage("Invalid arguments to absinthe_add_appId");
        return SERVICE_EINVALID;
    }

    asd->serviceData = svc_element;

    if (vendor)
    {
        if (asd->serviceVendor)
            snort_free(asd->serviceVendor);
        asd->serviceVendor = snort_strdup(vendor);
    }
    if (version)
    {
        if (asd->serviceVersion)
            snort_free(asd->serviceVersion);
        asd->serviceVersion = snort_strdup(version);
    }
    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->serviceAppId = appId;

    if (asd->get_session_flags(APPID_SESSION_IGNORE_HOST))
        return SERVICE_SUCCESS;

    if (!asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
        }
        if (asd->service_port)
            port = asd->service_port;
    }
    else
    {
        if (dir == APP_ID_FROM_INITIATOR)
        {
            ip = pkt->ptrs.ip_api.get_src();
            port = pkt->ptrs.sp;
        }
        else
        {
            ip = pkt->ptrs.ip_api.get_dst();
            port = pkt->ptrs.dp;
        }
    }

    // If UDP reversed, ensure we have the correct host tracker entry.
    if (asd->get_session_flags(APPID_SESSION_UDP_REVERSED))
        id_state = AppIdServiceState::get(ip, asd->protocol, port, get_service_detect_level(asd));

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (id_state->service_list)
        {
            id_state->free_service_match_list();
            id_state->current_service = nullptr;
        }

        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *ip;
            asd->service_port = port;
        }

        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
    }
    id_state->reset_time = 0;
    if (id_state->state != SERVICE_ID_VALID)
    {
        id_state->state = SERVICE_ID_VALID;
        id_state->valid_count = 0;
        id_state->detract_count = 0;
        id_state->last_detract.clear();
        id_state->invalid_client_count = 0;
        id_state->last_invalid_client.clear();
    }
    id_state->svc = svc_element;

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
            "Valid: %s:%u:%u %p %d\n",
            ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (void*)id_state, (int)id_state->state);

    if (!id_state->valid_count)
    {
        id_state->valid_count++;
        id_state->invalid_client_count = 0;
        id_state->last_invalid_client.clear();
        id_state->detract_count = 0;
        id_state->last_detract.clear();
    }
    else if (id_state->valid_count < STATE_ID_MAX_VALID_COUNT)
        id_state->valid_count++;

    /* Done looking for this session. */
    id_state->searching = false;

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "Service %d for protocol %u on port %u (%u->%u) is valid\n",
        (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
        (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
    return SERVICE_SUCCESS;
}

int AppIdServiceAddServiceSubtype(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, AppId appId, const char* vendor, const char* version,
    RNAServiceSubtype* subtype)
{
    asd->subtype = subtype;
    if (!svc_element->current_ref_count)
    {
        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid, but skipped\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
        return SERVICE_SUCCESS;
    }
    return AppIdServiceAddServiceEx(asd, pkt, dir, svc_element, appId, vendor, version);
}

int AppIdServiceAddService(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, AppId appId, const char* vendor, const char* version,
    const RNAServiceSubtype* subtype)
{
    RNAServiceSubtype* new_subtype = nullptr;

    if (!svc_element->current_ref_count)
    {
        APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "Service %d for protocol %u on port %u (%u->%u) is valid, but skipped\n",
            (int)appId, (unsigned)asd->protocol, (unsigned)asd->service_port,
            (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp);
        return SERVICE_SUCCESS;
    }

    for (; subtype; subtype = subtype->next)
    {
        RNAServiceSubtype* tmp_subtype = (RNAServiceSubtype*)snort_calloc(sizeof(RNAServiceSubtype));
        if (subtype->service)
            tmp_subtype->service = snort_strdup(subtype->service);

        if (subtype->vendor)
            tmp_subtype->vendor = snort_strdup(subtype->vendor);

        if (subtype->version)
            tmp_subtype->version = snort_strdup(subtype->version);

        tmp_subtype->next = new_subtype;
        new_subtype = tmp_subtype;
    }
    asd->subtype = new_subtype;
    return AppIdServiceAddServiceEx(asd, pkt, dir, svc_element, appId, vendor, version);
}

int AppIdServiceInProcess(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element)
{
    AppIdServiceIDState* id_state;

    if (!asd || !pkt)
    {
        ErrorMessage("Invalid arguments to service_in_process");
        return SERVICE_EINVALID;
    }

    if (dir == APP_ID_FROM_INITIATOR ||
        asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED))
        return SERVICE_SUCCESS;

    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    id_state = AppIdServiceState::get(ip, asd->protocol, port, get_service_detect_level(asd));
    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->svc = svc_element;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;
        }
    }

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,asd->service_ip,
            "Inprocess: %s:%u:%u %p %d\n", ipstr,
            (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
            (int)id_state->state);

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "Service for protocol %u on port %u is in process (%u->%u), %s\n",
        (unsigned)asd->protocol, (unsigned)asd->service_port, (unsigned)pkt->ptrs.sp,
        (unsigned)pkt->ptrs.dp,
        svc_element->name ? svc_element->name : "UNKNOWN");

    return SERVICE_SUCCESS;
}

/**Called when service can not be identified on a flow but the checks failed on client request
 * rather than server response. When client request fails a check, it may be specific to a client
 * therefore we should not fail the service right away. If the same behavior is seen from the same
 * client ultimately we will have to fail the service. If the same behavior is seen from different
 * clients going to same service then this most likely the service is something else.
 */
int AppIdServiceIncompatibleData(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index, const AppIdConfig*)
{
    if (!asd || !pkt)
    {
        ErrorMessage("Invalid arguments to service_incompatible_data");
        return SERVICE_EINVALID;
    }

    if (flow_data_index != APPID_SESSION_DATA_NONE)
        asd->free_flow_data_by_id(flow_data_index);

    /* If we're still working on a port/pattern list of detectors, then ignore
     * individual fails until we're done looking at everything. */
    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    AppIdServiceIDState* id_state = AppIdServiceState::get(ip, asd->protocol, port, get_service_detect_level(asd));
    if ( (asd->serviceData == nullptr) && (asd->candidate_service_list != nullptr)
        && (id_state != nullptr) )
    {
        if (sflist_count(asd->candidate_service_list) != 0)
        {
            return SERVICE_SUCCESS;
        }
        else if ((asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
            || (id_state->state == SERVICE_ID_BRUTE_FORCE) )
        {
            return SERVICE_SUCCESS;
        }
    }

    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->clear_session_flags(APPID_SESSION_CONTINUE);

    asd->serviceAppId = APP_ID_NONE;

    if (asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED)
                    || (svc_element && !svc_element->current_ref_count))
        return SERVICE_SUCCESS;

    if (dir == APP_ID_FROM_INITIATOR)
    {
        asd->set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return SERVICE_SUCCESS;
    }

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->svc = svc_element;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;

            APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
                "service_IC: Changed State to %s for protocol %u on port %u (%u->%u), count %u, %s\n",
                service_id_state_name[id_state->state], (unsigned)asd->protocol,
                (unsigned)asd->service_port,
                (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp, id_state->invalid_client_count,
                (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");
        }
        id_state->reset_time = 0;
    }

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
        "service_IC: State %s for protocol %u on port %u (%u->%u), count %u, %s\n",
        service_id_state_name[id_state->state], (unsigned)asd->protocol, (unsigned)asd->service_port,
        (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp, id_state->invalid_client_count,
        (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
            "Incompat: %s:%u:%u %p %d %s\n",
            ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
            (int)id_state->state,
            (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    return SERVICE_SUCCESS;
}

int AppIdServiceFailService(AppIdSession* asd, const Packet* pkt, int dir,
    const RNAServiceElement* svc_element, unsigned flow_data_index)
{
    const SfIp* ip = pkt->ptrs.ip_api.get_src();
    uint16_t port = asd->service_port ? asd->service_port : pkt->ptrs.sp;
    AppIdServiceIDState* id_state = AppIdServiceState::get(ip, asd->protocol, port, get_service_detect_level(asd));

    if (flow_data_index != APPID_SESSION_DATA_NONE)
        asd->free_flow_data_by_id(flow_data_index);

    /* If we're still working on a port/pattern list of detectors, then ignore
     * individual fails until we're done looking at everything. */
    if ( (asd->serviceData == nullptr) && (asd->candidate_service_list != nullptr)
        && (id_state != nullptr) )
    {
        if (sflist_count(asd->candidate_service_list) != 0)
            return SERVICE_SUCCESS;
        else if ( (asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
            || (id_state->state == SERVICE_ID_BRUTE_FORCE) )
            return SERVICE_SUCCESS;
    }

    asd->serviceAppId = APP_ID_NONE;

    asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
    asd->clear_session_flags(APPID_SESSION_CONTINUE);

    /* detectors should be careful in marking session UDP_REVERSED otherwise the same detector
     * gets all future flows. UDP_REVERSE should be marked only when detector positively
     * matches opposite direction patterns. */

    if (asd->get_session_flags(APPID_SESSION_IGNORE_HOST | APPID_SESSION_UDP_REVERSED)
            || (svc_element && !svc_element->current_ref_count))
        return SERVICE_SUCCESS;

    /* For subsequent packets, avoid marking service failed on client packet,
     * otherwise the service will show up on client side. */
    if (dir == APP_ID_FROM_INITIATOR)
    {
        asd->set_session_flags(APPID_SESSION_INCOMPATIBLE);
        return SERVICE_SUCCESS;
    }

    if ( !id_state )
    {
        id_state = AppIdServiceState::add(ip, asd->protocol, port, get_service_detect_level(asd));
        id_state->state = SERVICE_ID_NEW;
        id_state->svc = svc_element;
        asd->service_ip = *ip;
        asd->service_port = port;
    }
    else
    {
        if (!asd->service_ip.is_set())
        {
            asd->service_ip = *(pkt->ptrs.ip_api.get_src());
            if (!asd->service_port)
                asd->service_port = pkt->ptrs.sp;
        }
    }
    id_state->reset_time = 0;

    APPID_LOG_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp,
            "service_fail: State %s for protocol %u on port %u (%u->%u), count %u, valid count %u, currSvc %s\n",
            service_id_state_name[id_state->state], (unsigned)asd->protocol,
            (unsigned)asd->service_port, (unsigned)pkt->ptrs.sp, (unsigned)pkt->ptrs.dp,
            id_state->invalid_client_count, id_state->valid_count,
            (svc_element && svc_element->name) ? svc_element->name : "UNKNOWN");

    APPID_LOG_IP_FILTER_PORTS(pkt->ptrs.dp, pkt->ptrs.sp, asd->service_ip,
            "Fail: %s:%u:%u %p %d %s\n",
            ipstr, (unsigned)asd->protocol, (unsigned)asd->service_port, (void*)id_state,
            (int)id_state->state,
            (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    return SERVICE_SUCCESS;
}

/* Handle some exception cases on failure:
 *  - valid_count: If we have a detector that should be valid, but it keeps
 *    failing, consider restarting the detector search.
 *  - invalid_client_count: If our service detector search had trouble
 *    simply because of unrecognized client data, then consider retrying
 *    the search again. */
static void HandleFailure(AppIdSession* asd, AppIdServiceIDState* id_state,
        const SfIp* client_ip, unsigned timeout)
{
    /* If we had a valid detector, check for too many fails.  If so, start
     * search sequence again. */
    if (id_state->state == SERVICE_ID_VALID)
    {
        /* Too many invalid clients?  If so, count it as an invalid detect. */
        if (id_state->invalid_client_count >= STATE_ID_INVALID_CLIENT_THRESHOLD)
        {
            if (id_state->valid_count <= 1)
            {
                id_state->state = SERVICE_ID_NEW;
                id_state->invalid_client_count = 0;
                id_state->last_invalid_client.clear();
                id_state->valid_count = 0;
                id_state->detract_count = 0;
                id_state->last_detract.clear();
            }
            else
            {
                id_state->valid_count--;
                id_state->last_invalid_client = *client_ip;
                id_state->invalid_client_count = 0;
            }
        }
        /* Just a plain old fail.  If too many of these happen, start
         * search process over. */
        else if (id_state->invalid_client_count == 0)
        {
            if (id_state->last_detract.fast_eq6(*client_ip))
                id_state->detract_count++;
            else
                id_state->last_detract = *client_ip;

            if (id_state->detract_count >= STATE_ID_NEEDED_DUPE_DETRACT_COUNT)
            {
                if (id_state->valid_count <= 1)
                {
                    id_state->state = SERVICE_ID_NEW;
                    id_state->invalid_client_count = 0;
                    id_state->last_invalid_client.clear();
                    id_state->valid_count = 0;
                    id_state->detract_count = 0;
                    id_state->last_detract.clear();
                }
                else
                    id_state->valid_count--;
            }
        }
    }
    /* If we were port/pattern searching and timed out, just restart over next
     * time. */
    else if (timeout && (asd->candidate_service_list != nullptr))
    {
        id_state->state = SERVICE_ID_NEW;
    }
    /* If we were working on a port/pattern list of detectors, see if we
     * should restart search (because of invalid clients) or just let it
     * naturally continue onto brute force next. */
    else if (    (asd->candidate_service_list != nullptr)
        && (id_state->state == SERVICE_ID_BRUTE_FORCE) )
    {
        /* If we're getting some invalid clients, keep retrying
         * port/pattern search until we either find something or until we
         * just see too many invalid clients. */
        if (    (id_state->invalid_client_count > 0)
            && (id_state->invalid_client_count < STATE_ID_INVALID_CLIENT_THRESHOLD) )
        {
            id_state->state = SERVICE_ID_NEW;
        }
    }

    /* Done looking for this session. */
    id_state->searching = false;
}

/**Changes in_process service state to failed state when a flow is terminated.
 *
 * RNA used to repeat the same service detector if the detector remained in process till the flow terminated. Thus RNA
 * got stuck on this one detector and never tried another service detector. This function will treat such a detector
 * as returning incompatibleData when the flow is terminated. The intent here to make RNA try other service detectors but
 * unlike incompatibleData status, we dont want to undermine confidence in the service.
 *
 * @note Packet may be nullptr when this function is called upon session timeout.
 */
void FailInProcessService(AppIdSession* asd, const AppIdConfig*)
{
    if (asd->get_session_flags(APPID_SESSION_SERVICE_DETECTED | APPID_SESSION_UDP_REVERSED))
        return;

    AppIdServiceIDState* id_state = AppIdServiceState::get(&asd->service_ip, asd->protocol,
        asd->service_port, get_service_detect_level(asd));

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
            "FailInProcess %" PRIx64 ", %08X:%u proto %u\n", asd->common.flags,
            asd->common.initiator_ip.ip32[3], (unsigned)asd->service_port,
            (unsigned)asd->protocol);

    if (!id_state || (id_state->svc && !id_state->svc->current_ref_count))
        return;

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
            "FailInProcess: State %s for protocol %u on port %u, count %u, %s\n",
            service_id_state_name[id_state->state], (unsigned)asd->protocol,
            (unsigned)asd->service_port, id_state->invalid_client_count,
            (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");

    id_state->invalid_client_count += STATE_ID_INCONCLUSIVE_SERVICE_WEIGHT;
    if (asd->flow->server_ip.fast_eq6(asd->service_ip))
        HandleFailure(asd, id_state, &asd->flow->client_ip, 1);
    else
        HandleFailure(asd, id_state, &asd->flow->server_ip, 1);

    APPID_LOG_FILTER_SERVICE_PORT(asd->service_port,
            "FailInProcess: Changed State to %s for protocol %u on port %u, count %u, %s\n",
            service_id_state_name[id_state->state], (unsigned)asd->protocol,
            (unsigned)asd->service_port, id_state->invalid_client_count,
            (id_state->svc && id_state->svc->name) ? id_state->svc->name : "UNKNOWN");
}


/* This function should be called to find the next service detector to try when
 * we have not yet found a valid detector in the host tracker.  It will try
 * both port and/or pattern (but not brute force - that should be done outside
 * of this function).  This includes UDP reversed services.  A valid id_state
 * (even if just initialized to the NEW state) should exist before calling this
 * function.  The state coming out of this function will reflect the state in
 * which the next detector was found.  If nothing is found, it'll indicate that
 * brute force should be tried next as a state (and return nullptr).  This
 * function can be called once or multiple times (to run multiple detectors in
 * parallel) per flow.  Do not call this function if a detector has already
 * been specified (serviceData).  Basically, this function handles going
 * through the main port/pattern search (and returning which detector to add
 * next to the list of detectors to try (even if only 1)). */
static const RNAServiceElement* get_next_service(const Packet* p, const int dir,
    AppIdSession* asd, AppIdServiceIDState* id_state)
{
    auto proto = asd->protocol;

    /* If NEW, just advance onto trying ports. */
    if (id_state->state == SERVICE_ID_NEW)
    {
        id_state->state = SERVICE_ID_PORT;
        id_state->svc   = nullptr;
    }

    /* See if there are any port detectors to try.  If not, move onto patterns. */
    if (id_state->state == SERVICE_ID_PORT)
    {
        id_state->svc = AppIdGetNexServiceByPort(proto, (uint16_t)((dir ==
            APP_ID_FROM_RESPONDER) ? p->ptrs.sp : p->ptrs.dp), id_state->svc, asd);
        if (id_state->svc != nullptr)
        {
            return id_state->svc;
        }
        else
        {
            id_state->state = SERVICE_ID_PATTERN;
            id_state->svc   = nullptr;
            if (id_state->service_list != nullptr)
                id_state->current_service = id_state->service_list;
            else
                id_state->current_service = nullptr;
        }
    }

    if (id_state->state == SERVICE_ID_PATTERN)
    {
        /* If we haven't found anything yet, try to see if we get any hits
         * first with UDP reversed services before moving onto pattern matches. */
        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (!asd->get_session_flags(APPID_SESSION_ADDITIONAL_PACKET)
                    && (proto == IpProtocol::UDP) && !asd->tried_reverse_service )
            {
                SF_LNODE* iter;
                AppIdServiceIDState* reverse_id_state;
                const RNAServiceElement* reverse_service = nullptr;
                const SfIp* reverse_ip = p->ptrs.ip_api.get_src();
                asd->tried_reverse_service = true;
                if ((reverse_id_state = AppIdServiceState::get(reverse_ip, proto, p->ptrs.sp,
                        get_service_detect_level(asd))))
                {
                    reverse_service = reverse_id_state->svc;
                }

                if ( reverse_service
                    || (service_config->udp_reversed_services[p->ptrs.sp] &&
                    (reverse_service = ( RNAServiceElement*)sflist_first(
                        service_config->udp_reversed_services[p->ptrs.sp], &iter)))
                    || (p->dsize &&
                        (reverse_service = AppIdGetServiceByPattern(p, proto, dir, nullptr))) )
                {
                    id_state->svc = reverse_service;
                    return id_state->svc;
                }
            }
            return nullptr;
        }
        else
        {
            // Try pattern match detectors.  If not, give up, and go to brute force.
            if (id_state->service_list == nullptr)    /* no list yet (need to make one) */
                id_state->svc = AppIdGetServiceByPattern(p, proto, dir, id_state);
            else    /* already have a pattern service list (just use it) */
                id_state->svc = get_service_by_pattern(id_state, asd->service_port);

            if (id_state->svc != nullptr)
            {
                return id_state->svc;
            }
            else
            {
                id_state->state = SERVICE_ID_BRUTE_FORCE;
                id_state->svc   = nullptr;
                return nullptr;
            }
        }
    }

    /* Don't do anything if it was in VALID or BRUTE FORCE. */
    return nullptr;
}

int AppIdDiscoverService(Packet* p, const int dir, AppIdSession* asd)
{
    const SfIp* ip = nullptr;
    int ret = SERVICE_NOMATCH;
    const RNAServiceElement* service = nullptr;
    uint16_t port = 0;
    ServiceValidationArgs args;

    /* Get packet info. */
    auto proto = asd->protocol;
    if (asd->service_ip.is_set())
    {
        ip   = &asd->service_ip;
        port = asd->service_port;
    }
    else
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            ip   = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
        }
        else
        {
            ip   = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
        }
    }

    /* Get host tracker state. */
    AppIdServiceIDState* id_state = AppIdServiceState::get(ip, proto, port,
        get_service_detect_level(asd));
    if (id_state == nullptr)
        id_state = AppIdServiceState::add(ip, proto, port, get_service_detect_level(asd));

    if (asd->serviceData == nullptr)
    {
        /* If a valid service already exists in host tracker, give it a try. */
        if ((id_state->svc != nullptr) && (id_state->state == SERVICE_ID_VALID))
        {
            asd->serviceData = id_state->svc;
        }
        /* If we've gotten to brute force, give next detector a try. */
        else if ((id_state->state == SERVICE_ID_BRUTE_FORCE)
            && (asd->num_candidate_services_tried == 0)
            && !id_state->searching )
        {
            asd->serviceData = AppIdGetServiceByBruteForce(proto, id_state->svc);
            id_state->svc = asd->serviceData;
        }
    }

    args.data = p->data;
    args.size = p->dsize;
    args.dir = dir;
    args.asd = asd;
    args.pkt = p;
    args.pConfig = AppIdConfig::get_appid_config();
    args.session_logging_enabled = asd->session_logging_enabled;
    args.session_logging_id = asd->session_logging_id;

    /* If we already have a service to try, then try it out. */
    if (asd->serviceData != nullptr)
    {
        service = asd->serviceData;
        args.userdata = service->userdata;
        ret = service->validate(&args);
        if (ret == SERVICE_NOT_COMPATIBLE)
            asd->got_incompatible_services = true;
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s %s returned %d\n", asd->session_logging_id,
                service->name ? service->name : "UNKNOWN", ret);
    }
    else
    {
        if (asd->candidate_service_list == nullptr)
        {
            asd->candidate_service_list = (SF_LIST*)snort_calloc(sizeof(SF_LIST));
            sflist_init(asd->candidate_service_list);
            asd->num_candidate_services_tried = 0;

            /* This is our first time in for this session, and we're about to
             * search for a service, because we don't have any solid history on
             * this IP/port yet.  If some other session is also currently
             * searching on this host tracker entry, reset state here, so that
             * we can start search over again with this session. */
            if (id_state->searching)
                id_state->state = SERVICE_ID_NEW;
            id_state->searching = true;
        }

        /* See if we've got more detector(s) to add to the candidate list. */
        if (    (id_state->state == SERVICE_ID_NEW)
            || (id_state->state == SERVICE_ID_PORT)
            || ((id_state->state == SERVICE_ID_PATTERN) && (dir == APP_ID_FROM_RESPONDER)) )
        {
            while (asd->num_candidate_services_tried < MAX_CANDIDATE_SERVICES)
            {
                const RNAServiceElement* tmp = get_next_service(p, dir, asd, id_state);
                if (tmp != nullptr)
                {
                    SF_LNODE* iter = nullptr;
                    /* Add to list (if not already there). */
                    service = (RNAServiceElement*)sflist_first(asd->candidate_service_list,
                        &iter);
                    while (service && (service != tmp))
                        service = (RNAServiceElement*)sflist_next(&iter);
                    if (service == nullptr)
                    {
                        sflist_add_tail(asd->candidate_service_list, (void*)tmp);
                        asd->num_candidate_services_tried++;
                    }
                }
                else
                {
                    break;
                }
            }
        }

        /* Run all of the detectors that we currently have. */
        ret = SERVICE_INPROCESS;
        SF_LNODE* iter;
        service = (RNAServiceElement*)sflist_first(asd->candidate_service_list, &iter);
        const RNAServiceElement* failed_svc[MAX_CANDIDATE_SERVICES];
        unsigned num_failed = 0;
        while (service)
        {
            int result;

            args.userdata = service->userdata;
            result = service->validate(&args);
            if (result == SERVICE_NOT_COMPATIBLE)
                asd->got_incompatible_services = true;
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s %s returned %d\n", asd->session_logging_id,
                    service->name ? service->name : "UNKNOWN", result);

            if (result == SERVICE_SUCCESS)
            {
                ret = SERVICE_SUCCESS;
                asd->serviceData = service;
                sflist_free(asd->candidate_service_list);
                asd->candidate_service_list = nullptr;
                break;    /* done */
            }
            else if (result != SERVICE_INPROCESS)    /* fail */
               failed_svc[num_failed++] = service;

            service = (RNAServiceElement*)sflist_next(&iter);
        }

        for(unsigned i = 0; i < num_failed; i++)
        {
            SF_LNODE* iter;
            RNAServiceElement* service = (RNAServiceElement*)sflist_first(
                asd->candidate_service_list, &iter);

            if ( !service )
                break;

            while( service != failed_svc[i] )
                service = (RNAServiceElement*)sflist_next(&iter);

            sflist_remove_node(asd->candidate_service_list, iter);
        }

        /* If we tried everything and found nothing, then fail. */
        if (ret != SERVICE_SUCCESS)
        {
            if (    (sflist_count(asd->candidate_service_list) == 0)
                && (    (asd->num_candidate_services_tried >= MAX_CANDIDATE_SERVICES)
                || (id_state->state == SERVICE_ID_BRUTE_FORCE) ) )
            {
                AppIdServiceFailService(asd, p, dir, nullptr, APPID_SESSION_DATA_NONE);
                ret = SERVICE_NOMATCH;
            }
        }
    }

    if (service != nullptr)
    {
        id_state->reset_time = 0;
    }
    else if (dir == APP_ID_FROM_RESPONDER)    /* we have seen bidirectional exchange and have not
                                                 identified any service */
    {
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s no RNA service detector\n", asd->session_logging_id);
        AppIdServiceFailService(asd, p, dir, nullptr, APPID_SESSION_DATA_NONE);
        ret = SERVICE_NOMATCH;
    }

    /* Handle failure exception cases in states. */
    if ((ret != SERVICE_INPROCESS) && (ret != SERVICE_SUCCESS))
    {
        const SfIp* tmp_ip;
        if (dir == APP_ID_FROM_RESPONDER)
            tmp_ip = p->ptrs.ip_api.get_dst();
        else
            tmp_ip = p->ptrs.ip_api.get_src();

        if (asd->got_incompatible_services)
        {
            if (id_state->invalid_client_count < STATE_ID_INVALID_CLIENT_THRESHOLD)
            {
                if (id_state->last_invalid_client.fast_equals_raw(*tmp_ip))
                    id_state->invalid_client_count++;
                else
                {
                    id_state->invalid_client_count += 3;
                    id_state->last_invalid_client = *tmp_ip;
                }
            }
        }

        HandleFailure(asd, id_state, tmp_ip, 0);
    }

    /* Can free up any pattern match lists if done with them. */
    if (    (id_state->state == SERVICE_ID_BRUTE_FORCE)
        || (id_state->state == SERVICE_ID_VALID) )
    {
        id_state->free_service_match_list();
        id_state->current_service = nullptr;
    }

    return ret;
}

static void* service_flowdata_get(AppIdSession* asd, unsigned service_id)
{
    return asd->get_flow_data(service_id);
}

static int service_flowdata_add(AppIdSession* asd, void* data, unsigned service_id, AppIdFreeFCN
    fcn)
{
    return asd->add_flow_data(data, service_id, fcn);
}

static void dumpServices(FILE* stream, SF_LIST* const* parray)
{
    int i,n = 0;
    for (i = 0; i < RNA_SERVICE_MAX_PORT; i++)
    {
        if (parray[i] && (sflist_count(parray[i]) != 0))
        {
            if ( n !=  0)
                fprintf(stream," ");

            n++;
            fprintf(stream,"%d",i);
        }
    }
}

void dumpPorts(FILE* stream)
{
    fprintf(stream,"(tcp ");
    dumpServices(stream, service_config->tcp_services);
    fprintf(stream,") \n");
    fprintf(stream,"(udp ");
    dumpServices(stream, service_config->udp_services);
    fprintf(stream,") \n");
}

static void add_miscellaneous_info(AppIdSession* asd, AppId miscId)
{
    if (asd != nullptr)
        asd->misc_app_id = miscId;
}

static void add_dns_query_info(AppIdSession* asd, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint16_t record_type)
{
    if ( asd->dsession )
    {
        if ( ( asd->dsession->state != 0 ) && ( asd->dsession->id != id ) )
            reset_dns_info(asd);
    }
    else
        asd->dsession = (dnsSession*)snort_calloc(sizeof(dnsSession));

    if (asd->dsession->state & DNS_GOT_QUERY)
        return;
    asd->dsession->state |= DNS_GOT_QUERY;

    asd->dsession->id          = id;
    asd->dsession->record_type = record_type;

    if (!asd->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            asd->dsession->host_len    = host_len;
            asd->dsession->host_offset = host_offset;
            asd->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

static void add_dns_response_info(AppIdSession* asd, uint16_t id, const uint8_t* host,
        uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl)
{
    if ( asd->dsession )
    {
        if ( ( asd->dsession->state != 0 ) && ( asd->dsession->id != id ) )
            reset_dns_info(asd);
    }
    else
        asd->dsession = (dnsSession*)snort_calloc(sizeof(*asd->dsession));

    if (asd->dsession->state & DNS_GOT_RESPONSE)
        return;
    asd->dsession->state |= DNS_GOT_RESPONSE;

    asd->dsession->id            = id;
    asd->dsession->response_type = response_type;
    asd->dsession->ttl           = ttl;

    if (!asd->dsession->host)
    {
        if ((host != nullptr) && (host_len > 0) && (host_offset > 0))
        {
            asd->dsession->host_len    = host_len;
            asd->dsession->host_offset = host_offset;
            asd->dsession->host        = dns_parse_host(host, host_len);
        }
    }
}

static void reset_dns_info(AppIdSession* asd)
{
    if (asd->dsession)
    {
        snort_free(asd->dsession->host);
        memset(asd->dsession, 0, sizeof(*(asd->dsession)));
    }
}
