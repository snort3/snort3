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

// appid_config.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_config.h"

#include <glob.h>
#include <climits>

#include "app_forecast.h"
#include "app_info_table.h"
#include "appid_discovery.h"
#include "appid_session.h"
#ifdef USE_RNA_CONFIG
#include "appid_utils/network_set.h"
#include "appid_utils/ip_funcs.h"
#endif
#include "detector_plugins/detector_pattern.h"
#include "host_port_app_cache.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "lua_detector_module.h"
#include "utils/util.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "target_based/snort_protocols.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_lib_handler.h"
#endif

using namespace snort;

#define ODP_PORT_DETECTORS "odp/port/*"
#define CUSTOM_PORT_DETECTORS "custom/port/*"
#define MAX_DISPLAY_SIZE   65536
#define MAX_LINE    2048

using namespace snort;

uint32_t app_id_netmasks[33] =
{ 0x00000000, 0x80000000, 0xC0000000, 0xE0000000, 0xF0000000, 0xF8000000, 0xFC000000,
  0xFE000000, 0xFF000000, 0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000, 0xFFF80000,
  0xFFFC0000, 0xFFFE0000, 0xFFFF0000, 0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
  0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0,
  0xFFFFFFF0, 0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF };

struct PortList
{
    PortList* next;
    uint16_t port;
};

SnortProtocolId snortId_for_unsynchronized;
SnortProtocolId snortId_for_ftp_data;
SnortProtocolId snortId_for_http2;

static void map_app_names_to_snort_ids(SnortConfig* sc)
{
    /* init globals for snortId compares */
    snortId_for_unsynchronized = sc->proto_ref->add("unsynchronized");
    snortId_for_ftp_data = sc->proto_ref->add("ftp-data");
    snortId_for_http2    = sc->proto_ref->add("http2");

    // Have to create SnortProtocolIds during configuration initialization.
    sc->proto_ref->add("rexec");
    sc->proto_ref->add("rsh-error");
    sc->proto_ref->add("snmp");
    sc->proto_ref->add("sunrpc");
    sc->proto_ref->add("tftp");
}

AppIdModuleConfig::~AppIdModuleConfig()
{
#ifdef USE_RNA_CONFIG
    snort_free((void*)conf_file);
#endif
    snort_free((void*)app_detector_dir);
}

//FIXIT-M: RELOAD - move initialization back to AppIdConfig
//class constructor
AppInfoManager& AppIdConfig::app_info_mgr = AppInfoManager::get_instance();

AppIdConfig::AppIdConfig(AppIdModuleConfig* config)
    : mod_config(config)
{
#ifdef USE_RNA_CONFIG
    for ( unsigned i = 0; i < MAX_ZONES; i++ )
        net_list_by_zone[ i ] = nullptr;
#endif

    for ( unsigned i = 0; i < 65535; i++ )
    {
        tcp_port_only[ i ] = APP_ID_NONE;
        udp_port_only[ i ] = APP_ID_NONE;
    }

    for ( unsigned i = 0; i < 255; i++ )
        ip_protocol[ i ] = APP_ID_NONE;

    for ( unsigned i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++ )
    {
        tcp_port_exclusions_src[ i ] = nullptr;
        udp_port_exclusions_src[ i ] = nullptr;
        tcp_port_exclusions_dst[ i ] = nullptr;
        udp_port_exclusions_dst[ i ] = nullptr;
    }
}

AppIdConfig::~AppIdConfig()
{
    cleanup();
}

//FIXIT-M: RELOAD - Move app info tabe cleanup back 
//to AppId config destructor - cleanup()
void AppIdConfig::pterm()
{
    AppIdConfig::app_info_mgr.cleanup_appid_info_table();
}

void AppIdConfig::read_port_detectors(const char* files)
{
    int rval;
    glob_t globs;
    char pattern[PATH_MAX];
    uint32_t n;

    snprintf(pattern, sizeof(pattern), "%s/%s", mod_config->app_detector_dir, files);

    memset(&globs, 0, sizeof(globs));
    rval = glob(pattern, 0, nullptr, &globs);
    if (rval != 0 && rval != GLOB_NOMATCH)
    {
        ErrorMessage("Unable to read directory '%s'\n",pattern);
        return;
    }

    for (n = 0; n < globs.gl_pathc; n++)
    {
        FILE* file;
        unsigned proto = 0;
        AppId appId = APP_ID_NONE;
        char line[1024];
        PortList* port = nullptr;
        PortList* tmp_port;

        if ((file = fopen(globs.gl_pathv[n], "r")) == nullptr)
        {
            ErrorMessage("Unable to read port service '%s'\n",globs.gl_pathv[n]);
            continue;
        }

        while (fgets(line, sizeof(line), file))
        {
            char* key, * value, * p;
            size_t len;

            len = strlen(line);
            for (; len && (line[len - 1] == '\n' || line[len - 1] == '\r'); len--)
                line[len - 1] = 0;

            /* find key/value for lines of the format "key: value\n" */
            if ((value = strchr(line, ':')))
            {
                key = line;
                *value = '\0';
                value++;
                while (*value == ' ')
                    value++;

                if (strcasecmp(key, "ports") == 0)
                {
                    char* context = nullptr;
                    char* ptr;
                    unsigned long tmp;

                    for (ptr = strtok_r(value, ",", &context); ptr; ptr = strtok_r(nullptr, ",",
                            &context))
                    {
                        while (*ptr == ' ')
                            ptr++;
                        len = strlen(ptr);
                        for (; len && ptr[len - 1] == ' '; len--)
                            ptr[len - 1] = 0;
                        tmp = strtoul(ptr, &p, 10);
                        if (!*ptr || *p || !tmp || tmp > 65535)
                        {
                            ErrorMessage("Invalid port, '%s', in lua detector '%s'\n",ptr,
                                globs.gl_pathv[n]);
                            goto next;
                        }
                        tmp_port = (PortList*)snort_calloc(sizeof(PortList));
                        tmp_port->port = (uint16_t)tmp;
                        tmp_port->next = port;
                        port = tmp_port;
                    }
                }
                else if (strcasecmp(key, "protocol") == 0)
                {
                    if (strcasecmp(value, "tcp") == 0)
                        proto = 1;
                    else if (strcasecmp(value, "udp") == 0)
                        proto = 2;
                    else if (strcasecmp(value, "tcp/udp") == 0)
                        proto = 3;
                    else
                    {
                        ErrorMessage("Invalid protocol, '%s', in port service '%s'\n",value,
                            globs.gl_pathv[n]);
                        goto next;
                    }
                }
                else if (strcasecmp(key, "appId") == 0)
                {
                    appId = (AppId)strtoul(value, &p, 10);
                    if (!*value || *p || appId <= APP_ID_NONE)
                    {
                        ErrorMessage("Invalid app ID, '%s', in port service '%s'\n",value,
                            globs.gl_pathv[n]);
                        goto next;
                    }
                }
            }
        }

        if (port && proto && appId > APP_ID_NONE)
        {
            while ((tmp_port = port))
            {
                port = tmp_port->next;
                if (proto & 1)
                    tcp_port_only[tmp_port->port] = appId;
                if (proto & 2)
                    udp_port_only[tmp_port->port] = appId;

                snort_free(tmp_port);
                AppIdConfig::app_info_mgr.set_app_info_active(appId);
            }
            AppIdConfig::app_info_mgr.set_app_info_active(appId);
        }
        else
            ErrorMessage("Missing parameter(s) in port service '%s'\n",globs.gl_pathv[n]);

next:   ;
        while ((tmp_port = port))
        {
            port = tmp_port->next;
            snort_free(tmp_port);
        }
        fclose(file);
    }

    globfree(&globs);
}

#ifdef USE_RNA_CONFIG
void AppIdConfig::configure_analysis_networks(char* toklist[], uint32_t flag)
{
    NetworkSet* my_net_list;
    RNAIpv6AddrSet* ias6;
    char* p;

    if (toklist[0])
    {
        if (strchr(toklist[0], ':'))
        {
            ias6 = ParseIpv6Cidr(toklist[0]);
            if (ias6)
            {
                NSIPv6Addr six;
                char min_ip[INET6_ADDRSTRLEN];
                char max_ip[INET6_ADDRSTRLEN];
                int zone;

                if (toklist[1])
                {
                    long tmp = strtol(toklist[1], &p, 10);

                    if (!*toklist[1] || *p != 0 || tmp >= MAX_ZONES || tmp < -1)
                    {
                        ErrorMessage("Invalid Analyze: %s '%s'", toklist[0], toklist[1]);
                        zone = -1;
                    }
                    else
                        zone = (int)tmp;
                }
                else
                    zone = -1;
                ias6->addr_flags |= flag;
                six = ias6->range_min;
                NetworkSetManager::ntoh_ipv6(&six);
                inet_ntop(AF_INET6, (struct in6_addr*)&six, min_ip, sizeof(min_ip));
                six = ias6->range_max;
                NetworkSetManager::ntoh_ipv6(&six);
                inet_ntop(AF_INET6, (struct in6_addr*)&six, max_ip, sizeof(max_ip));
                if (zone >= 0)
                {
                    if (!(my_net_list = net_list_by_zone[zone]))
                    {
                        if (NetworkSetManager::create(&my_net_list))
                            ErrorMessage("%s", "Failed to create a network set");
                        else
                        {
                            my_net_list->next = net_list_list;
                            net_list_list = my_net_list;
                        }
                        net_list_by_zone[zone] = my_net_list;
                    }
                }
                else
                    my_net_list = net_list;
                if (my_net_list && NetworkSetManager::add_cidr_block6_ex(my_net_list,
                    &ias6->range_min, ias6->netmask, ias6->addr_flags & IPFUNCS_EXCEPT_IP, 0,
                    ias6->addr_flags & (~IPFUNCS_EXCEPT_IP)))
                {
                    ErrorMessage(
                        "Failed to add an IP address set to the list of monitored networks");
                }
                snort_free(ias6);
            }
            else
                ErrorMessage("Invalid analysis parameter: %s", toklist[0]);
        }
        else
        {
            RNAIpAddrSet* ias = ParseIpCidr(toklist[0], app_id_netmasks);

            if (ias)
            {
                int zone;

                if (toklist[1])
                {
                    unsigned long tmp = strtol(toklist[1], &p, 10);

                    if (!*toklist[1] || *p != 0 || tmp >= MAX_ZONES || tmp < -1)
                    {
                        ErrorMessage("Invalid Analyze: %s '%s'", toklist[0], toklist[1]);
                        zone = -1;
                    }
                    else
                        zone = (int)tmp;
                }
                else
                    zone = -1;
                ias->addr_flags |= flag;
                if (zone >= 0)
                {
                    if (!(my_net_list = net_list_by_zone[zone]))
                    {
                        if (NetworkSetManager::create(&my_net_list))
                            ErrorMessage("%s", "Failed to create a network set");
                        else
                        {
                            my_net_list->next = net_list_list;
                            net_list_list = my_net_list;
                        }
                        net_list_by_zone[zone] = my_net_list;
                    }
                }
                else
                    my_net_list = net_list;
                if (my_net_list && NetworkSetManager::add_cidr_block_ex(my_net_list,
                    ias->range_min,
                    ias->netmask,
                    ias->addr_flags & IPFUNCS_EXCEPT_IP, 0,
                    ias->addr_flags & (~IPFUNCS_EXCEPT_IP)))
                {
                    ErrorMessage(
                        "Failed to add an IP address set to the list of monitored networks");
                }
                snort_free(ias);
            }
            else
                ErrorMessage("Invalid analysis parameter: %s", toklist[0]);
        }
    }
}

int AppIdConfig::add_port_exclusion(AppIdPortExclusions& port_exclusions, const
    ip::snort_in6_addr* ip,
    const ip::snort_in6_addr* netmask, int family, uint16_t port)
{
    SF_LIST* pe_list;

    PortExclusion* port_ex = (PortExclusion*)snort_calloc(sizeof(PortExclusion));
    port_ex->ip = *ip;
    if (family == AF_INET)
    {
        port_ex->netmask.u6_addr32[0] = port_ex->netmask.u6_addr32[1] =
                port_ex->netmask.u6_addr32[2] = ~0;
        port_ex->netmask.u6_addr32[3] = netmask->u6_addr32[3];
    }
    else
        port_ex->netmask = *netmask;

    if ((pe_list = port_exclusions[port]) == nullptr)
    {
        pe_list = port_exclusions[port] = sflist_new();
        if (pe_list == nullptr)
        {
            snort_free(port_ex);
            ErrorMessage("Config: Failed to allocate memory for port exclusion list");
            return -1;
        }
    }

    /* add this PortExclusion to the sflist for this port */
    sflist_add_tail(pe_list, port_ex);
    return 0;
}

void AppIdConfig::process_port_exclusion(char* toklist[])
{
    int i = 1;
    char* p;
    RNAIpv6AddrSet* ias6;
    IpProtocol proto;
    unsigned long dir;
    unsigned long port;
    ip::snort_in6_addr ip;
    ip::snort_in6_addr netmask;
    int family;

    if (!toklist[i])
    {
        ErrorMessage("Config: Port exclusion direction omitted");
        return;
    }

    if (strcasecmp(toklist[i], "dst") == 0)
        dir = 2;
    else if (strcasecmp(toklist[i], "src") == 0)
        dir = 1;
    else if (strcasecmp(toklist[i], "both") == 0)
        dir = 3;
    else
    {
        ErrorMessage("Config: Invalid port exclusion direction specified");
        return;
    }

    i++;
    if (!toklist[i])
    {
        ErrorMessage("Config: Port exclusion protocol omitted");
        return;
    }

    if (strcasecmp(toklist[i], "tcp") == 0)
        proto = IpProtocol::TCP;
    else if (strcasecmp(toklist[i], "udp") == 0)
        proto = IpProtocol::UDP;
    else
    {
        ErrorMessage("Config: Invalid port exclusion protocol specified");
        return;
    }

    i++;
    if (!toklist[i])
    {
        ErrorMessage("Config: Port exclusion port omitted");
        return;
    }

    port = strtoul(toklist[i], &p, 10);
    if (!*toklist[i] || *p || port >= APP_ID_PORT_ARRAY_SIZE)
    {
        ErrorMessage("Config: Invalid port exclusion port specified");
        return;
    }

    i++;
    if (!toklist[i])
    {
        ErrorMessage("Config: Port exclusion address omitted");
        return;
    }

    if (strchr(toklist[i], ':'))
    {
        ias6 = ParseIpv6Cidr(toklist[i]);
        if (!ias6 || ias6->addr_flags)
        {
            if (ias6)
                snort_free(ias6);
            ErrorMessage("Config: Invalid port exclusion address specified");
            return;
        }
        NetworkSetManager::hton_swap_ipv6(&ias6->range_min, &ip);
        NetworkSetManager::hton_swap_ipv6(&ias6->netmask_mask, &netmask);
        family = AF_INET6;
        snort_free(ias6);
    }
    else
    {
        RNAIpAddrSet* ias = ParseIpCidr(toklist[i], app_id_netmasks);
        if (!ias || ias->addr_flags)
        {
            if (ias)
                snort_free(ias);
            ErrorMessage("Config: Invalid port exclusion address specified");
            return;
        }
        family = AF_INET;
        copyIpv4ToIpv6Network(&ip, htonl(ias->range_min));
        copyIpv4ToIpv6Network(&netmask, htonl(ias->netmask_mask));
        snort_free(ias);
    }

    if (dir & 1)
    {
        if (proto == IpProtocol::TCP)
            add_port_exclusion(tcp_port_exclusions_src, &ip, &netmask, family, (uint16_t)port);
        else
            add_port_exclusion(udp_port_exclusions_src, &ip, &netmask, family, (uint16_t)port);
    }

    if (dir & 2)
    {
        if (proto == IpProtocol::TCP)
            add_port_exclusion(tcp_port_exclusions_dst, &ip, &netmask, family, (uint16_t)port);
        else
            add_port_exclusion(udp_port_exclusions_dst, &ip, &netmask, family, (uint16_t)port);
    }
}

void AppIdConfig::process_config_directive(char* toklist[], int /* reload */)
{
    char* curtok;
    int i;

    /* the first tok is "config" or we wouldn't be here now */
    i = 1;
    curtok = toklist[i];
    i++;

    if (!strcasecmp(curtok, "Analyze"))
    {
        configure_analysis_networks(&toklist[i], IPFUNCS_HOSTS_IP | IPFUNCS_APPLICATION);
    }
    else if (!strcasecmp(curtok, "AnalyzeHost"))
    {
        configure_analysis_networks(&toklist[i], IPFUNCS_HOSTS_IP | IPFUNCS_APPLICATION);
    }
    else if (!strcasecmp(curtok, "AnalyzeUser"))
    {
        configure_analysis_networks(&toklist[i], IPFUNCS_USER_IP | IPFUNCS_APPLICATION);
    }
    else if (!strcasecmp(curtok, "AnalyzeHostUser"))
    {
        configure_analysis_networks(&toklist[i],
            IPFUNCS_HOSTS_IP | IPFUNCS_USER_IP | IPFUNCS_APPLICATION);
    }
    else if (!strcasecmp(curtok, "AnalyzeApplication"))
    {
        configure_analysis_networks(&toklist[i], IPFUNCS_APPLICATION);
    }
}

static int strip(char* data)
{
    int size;
    char* idx;

    idx = data;
    size = 0;

    while (*idx)
    {
        if ((*idx == '\n') || (*idx == '\r'))
        {
            *idx = 0;
            break;
        }
        if (*idx == '\t')
        {
            *idx = ' ';
        }
        size++;
        idx++;
    }

    return size;
}

#define MAX_TOKS    256
static int tokenize(char* data, char* toklist[])
{
    char** ap;
    int argcount = 0;
    int i = 0;
    int drop_further = 0;

    for (ap = (char**)toklist; ap < &toklist[MAX_TOKS] && (*ap = strsep(&data, " ")) != nullptr; )
    {
        if (**ap != '\0')
        {
            ap++;
            argcount++;
        }
    }

    *ap = nullptr;

    /* scan for comments */
    while (i < argcount)
    {
        char* tok = toklist[i];

        if (tok[0] == '#' && !drop_further)
        {
            argcount = i;
            drop_further = 1;
        }

        if (drop_further)
        {
            toklist[i] = nullptr;
        }

        i++;
    }

    return argcount;
}

int AppIdConfig::load_analysis_config(const char* config_file, int reload, int instance_id)
{
    char linebuffer[MAX_LINE];
    char* toklist[MAX_TOKS];
    NetworkSet* my_net_list;

    if (NetworkSetManager::create(&net_list))
        FatalError("Failed to allocate a network set");
    net_list_list = net_list;

    if (!config_file || (!config_file[0]))
    {
        char addrString[sizeof("0.0.0.0/0")];
        toklist[1] = nullptr;
        toklist[0] = addrString;
        strcpy(addrString,"0.0.0.0/0");
        configure_analysis_networks(toklist, IPFUNCS_HOSTS_IP | IPFUNCS_USER_IP |
            IPFUNCS_APPLICATION);
        strcpy(addrString,"::/0");
        configure_analysis_networks(toklist, IPFUNCS_HOSTS_IP | IPFUNCS_USER_IP |
            IPFUNCS_APPLICATION);
        toklist[0] = nullptr;
    }
    else
    {
        FILE* fp;

        if (!(fp = fopen(config_file, "r")))
        {
            ErrorMessage("Unable to open %s", config_file);
            return -1;
        }
        unsigned line = 0;

        while (fgets(linebuffer, MAX_LINE, fp) != nullptr)
        {
            line++;
            strip(linebuffer);
            char* cptr = linebuffer;

            while (isspace((int)*cptr))
                cptr++;

            if (*cptr && (*cptr != '#') && (*cptr != 0x0a))
            {
                memset(toklist, 0, sizeof(toklist));

                if (tokenize(cptr, toklist) < 2)
                {
                    fclose(fp);
                    ErrorMessage("Invalid configuration file line %u", line);
                    return -1;
                }
                if (!(strcasecmp(toklist[0], "config")))
                    process_config_directive(toklist, reload);
                else if (!(strcasecmp(toklist[0], "portexclusion")))
                    process_port_exclusion(toklist);
            }
        }

        fclose(fp);
    }

    if (instance_id)
    {
        char* instance_toklist[2];
        char addrString[sizeof("0.0.0.0/0")];
        instance_toklist[0] = addrString;
        instance_toklist[1] = nullptr;
        strcpy(addrString,"0.0.0.0/0");
        configure_analysis_networks(instance_toklist, IPFUNCS_APPLICATION);
        strcpy(addrString,"::/0");
        configure_analysis_networks(instance_toklist, IPFUNCS_APPLICATION);
    }

    for (my_net_list = net_list_list; my_net_list; my_net_list = net_list->next)
    {
        if (my_net_list != net_list)
        {
            if (NetworkSetManager::add_set(my_net_list, net_list))
                ErrorMessage("Failed to add any network list to a zone network list");
        }
    }
    net_list_count = 0;
    for (my_net_list = net_list_list; my_net_list; my_net_list = net_list->next)
    {
        if (NetworkSetManager::reduce(my_net_list))
            ErrorMessage("Failed to reduce the IP address sets");
        net_list_count += NetworkSetManager::count_ex(my_net_list) + NetworkSetManager::count6_ex(
            my_net_list);
    }

    return 0;
}

#endif

void AppIdConfig::set_safe_search_enforcement(bool enabled)
{
    mod_config->safe_search_enabled = enabled;
}

bool AppIdConfig::init_appid(SnortConfig* sc, AppIdInspector *ins)
{
    //FIXIT -M: RELOAD - Get rid of "once" flag
    //Handle the if condition in AppIdConfig::init_appid
    static bool once = false;
    if (!once)
    {      
        AppIdConfig::app_info_mgr.init_appid_info_table(mod_config, sc);
        HostPortCache::initialize();
        HttpPatternMatchers* http_matchers = HttpPatternMatchers::get_instance();
        AppIdDiscovery::initialize_plugins(ins);
        init_length_app_cache();
        LuaDetectorManager::initialize(*this, 1);
        PatternServiceDetector::finalize_service_port_patterns();
        PatternClientDetector::finalize_client_port_patterns();
        AppIdDiscovery::finalize_plugins();
        http_matchers->finalize_patterns();
	    ssl_detector_process_patterns();
        dns_host_detector_process_patterns();
        read_port_detectors(ODP_PORT_DETECTORS);
        read_port_detectors(CUSTOM_PORT_DETECTORS);
        once = true;
    }
#ifdef USE_RNA_CONFIG
    load_analysis_config(mod_config->conf_file, 0, mod_config->instance_id);
#endif

#ifdef ENABLE_APPID_THIRD_PARTY
    TPLibHandler::pinit(mod_config);
#endif
    map_app_names_to_snort_ids(sc);
    return true;
}

static void free_port_exclusion_list(AppIdPortExclusions& pe_list)
{
    for ( unsigned i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++ )
    {
        if ( pe_list[i] != nullptr )
        {
            sflist_free_all(pe_list[i], &snort_free);
            pe_list[i] = nullptr;
        }
    }
}

void AppIdConfig::cleanup()
{
#ifdef USE_RNA_CONFIG
    NetworkSet* net_list;          ///< list of network sets
    while ((net_list = net_list_list))
    {
        net_list_list = net_list->next;
        NetworkSetManager::destroy(net_list);
    }
#endif

    free_port_exclusion_list(tcp_port_exclusions_src);
    free_port_exclusion_list(tcp_port_exclusions_dst);
    free_port_exclusion_list(udp_port_exclusions_src);
    free_port_exclusion_list(udp_port_exclusions_dst);
}

AppId AppIdConfig::get_port_service_id(IpProtocol proto, uint16_t port)
{
    AppId appId;

    if (proto == IpProtocol::TCP)
        appId = tcp_port_only[port];
    else if (proto == IpProtocol::UDP)
        appId = udp_port_only[port];
    else
        appId = ip_protocol[(uint16_t)proto];

    return appId;
}

static void display_port_exclusion_list(SF_LIST* pe_list, uint16_t port)
{
    char inet_buffer[INET6_ADDRSTRLEN];
    char inet_buffer2[INET6_ADDRSTRLEN];
    PortExclusion* pe;
    SF_LNODE* lnext;

    if (!pe_list)
        return;

    for (pe = (PortExclusion*)sflist_first(pe_list, &lnext);
        pe;
        pe = (PortExclusion*)sflist_next(&lnext))
    {
        const char* p = inet_ntop(pe->family, &pe->ip, inet_buffer, sizeof(inet_buffer));
        const char* p2 = inet_ntop(pe->family, &pe->netmask, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %d on %s/%s\n", port, p ? p : "ERROR", p2 ? p2 : "ERROR");
    }
}

void AppIdConfig::show()
{
    unsigned i;

    if (!mod_config->tp_appid_path.empty())
        LogMessage("    3rd Party Dir: %s\n", mod_config->tp_appid_path.c_str());

#ifdef USE_RNA_CONFIG
    struct in_addr ia;
    NSIPv6Addr six;
    char inet_buffer[INET6_ADDRSTRLEN];
    char inet_buffer2[INET6_ADDRSTRLEN];
    const char* p;
    const char* p2;

    LogMessage("    Monitoring Networks for any zone:\n");
    for (i = 0; i < net_list->count; i++)
    {
        ia.s_addr = htonl(net_list->pnetwork[i]->range_min);
        p = inet_ntop(AF_INET, &ia, inet_buffer, sizeof(inet_buffer));
        ia.s_addr = htonl(net_list->pnetwork[i]->range_max);
        p2 = inet_ntop(AF_INET, &ia, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %s%s-%s %04X\n", (net_list->pnetwork[i]->info.ip_not) ? "!" : "",
            p ?
            p : "ERROR",
            p2 ? p2 : "ERROR", net_list->pnetwork[i]->info.type);
    }
    for (i = 0; i < net_list->count6; i++)
    {
        six = net_list->pnetwork6[i]->range_min;
        NetworkSetManager::ntoh_ipv6(&six);
        p = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer, sizeof(inet_buffer));
        six = net_list->pnetwork6[i]->range_max;
        NetworkSetManager::ntoh_ipv6(&six);
        p2 = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %s%s-%s %04X\n", (net_list->pnetwork6[i]->info.ip_not) ? "!" : "",
            p ?
            p : "ERROR",
            p2 ? p2 : "ERROR", net_list->pnetwork6[i]->info.type);
    }

    for (int j = 0; j < MAX_ZONES; j++)
    {
        if (!(net_list = net_list_by_zone[j]))
            continue;
        LogMessage("    Monitoring Networks for zone %d:\n", j);
        for (i = 0; i < net_list->count; i++)
        {
            ia.s_addr = htonl(net_list->pnetwork[i]->range_min);
            p = inet_ntop(AF_INET, &ia, inet_buffer, sizeof(inet_buffer));
            ia.s_addr = htonl(net_list->pnetwork[i]->range_max);
            p2 = inet_ntop(AF_INET, &ia, inet_buffer2, sizeof(inet_buffer2));
            LogMessage("        %s%s-%s %04X\n", (net_list->pnetwork[i]->info.ip_not) ? "!" :
                "",
                p ? p : "ERROR",
                p2 ? p2 : "ERROR", net_list->pnetwork[i]->info.type);
        }
        for (i = 0; i < net_list->count6; i++)
        {
            six = net_list->pnetwork6[i]->range_min;
            NetworkSetManager::ntoh_ipv6(&six);
            p = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer, sizeof(inet_buffer));
            six = net_list->pnetwork6[i]->range_max;
            NetworkSetManager::ntoh_ipv6(&six);
            p2 = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer2, sizeof(inet_buffer2));
            LogMessage("        %s%s-%s %04X\n", (net_list->pnetwork6[i]->info.ip_not) ? "!" :
                "",
                p ? p : "ERROR",
                p2 ? p2 : "ERROR", net_list->pnetwork6[i]->info.type);
        }
    }
#endif

    LogMessage("    Excluded TCP Ports for Src:\n");
    for (i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++)
        display_port_exclusion_list(tcp_port_exclusions_src[i], i);

    LogMessage("    Excluded TCP Ports for Dst:\n");
    for (i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++)
        display_port_exclusion_list(tcp_port_exclusions_dst[i], i);

    LogMessage("    Excluded UDP Ports Src:\n");
    for (i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++)
        display_port_exclusion_list(udp_port_exclusions_src[i], i);

    LogMessage("    Excluded UDP Ports Dst:\n");
    for (i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++)
        display_port_exclusion_list(udp_port_exclusions_dst[i], i);
}

void AppIdConfig::display_port_config()
{
    bool first = true;

    for ( auto& i : tcp_port_only )
        if (tcp_port_only[i])
        {
            if (first)
            {
                LogMessage("    TCP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, tcp_port_only[i]);
        }

    first = true;
    for ( auto& i : udp_port_only )
        if (udp_port_only[i])
        {
            if (first)
            {
                LogMessage("    UDP Port-Only Services\n");
                first = false;
            }
            LogMessage("        %5u - %u\n", i, udp_port_only[i]);
        }
}

