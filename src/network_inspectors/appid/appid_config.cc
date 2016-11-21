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

// appid_config.cc author Sourcefire Inc.
#include <cstring>
#include <glob.h>

#include "appid_config.h"
#include "app_info_table.h"
#include "appid_utils/network_set.h"
#include "appid_utils/ip_funcs.h"
#include "appid_utils/appid_utils.h"
#include "main/snort_debug.h"
#include "log/messages.h"
#include "utils/util.h"
#include "thirdparty_appid_utils.h"
#include "service_plugins/service_base.h"

#define ODP_PORT_DETECTORS "odp/port/*"
#define CUSTOM_PORT_DETECTORS "custom/port/*"
#define MAX_DISPLAY_SIZE   65536
#define MAX_LINE    2048

static AppIdConfig* appid_config = nullptr;
unsigned appIdPolicyId;
uint32_t app_id_netmasks[33];

struct PortList
{
    PortList* next;
    uint16_t port;
};

static THREAD_LOCAL SF_LIST appid_custom_configs;

AppIdModuleConfig::AppIdModuleConfig()
{
    session_log_filter.sip.clear();
    session_log_filter.dip.clear();
}

AppIdModuleConfig::~AppIdModuleConfig()
{
    snort_free((void*)conf_file);
    snort_free((void*)app_detector_dir);
    snort_free((void*)thirdparty_appid_dir);
    appid_config = nullptr;

}

AppIdConfig::AppIdConfig( AppIdModuleConfig* config )
     : mod_config( config ), app_info_mgr(AppInfoManager::get_instance())
{
    for( unsigned i = 0; i < MAX_ZONES; i++ )
        net_list_by_zone[ i ] = nullptr;

    for( unsigned i = 0; i < 65535; i++ )
    {
        tcp_port_only[ i ] = APP_ID_NONE;
        udp_port_only[ i ] = APP_ID_NONE;
    }

    for( unsigned i = 0; i < 255; i++ )
        ip_protocol[ i ] = APP_ID_NONE;

    for( unsigned i = 0; i < APP_ID_PORT_ARRAY_SIZE; i++ )
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

AppIdConfig* AppIdConfig::get_appid_config()
{
    return appid_config;
}

void AppidConfigElement::add_generic_config_element(const char* name, void* data)
{
    AppidConfigElement* ce;

    ce = (AppidConfigElement*)snort_calloc(sizeof(AppidConfigElement));
    ce->name = snort_strdup(name);
    ce->value = data;
    sflist_add_tail(&appid_custom_configs, ce);
}

void* AppidConfigElement::find_generic_config_element(const char* name)
{
    AppidConfigElement* ce;
    SF_LNODE* next;

    // Search a module's configuration by its name
    for (ce = (AppidConfigElement*)sflist_first(&appid_custom_configs, &next);
         ce != nullptr;
         ce = (AppidConfigElement*)sflist_next(&next))
    {
        if (strcmp(ce->name, name) == 0)
            return ce->value;
    }

    return nullptr;
}

void AppidConfigElement::remove_generic_config_element(const char* name)
{
    SF_LNODE* iter;
    AppidConfigElement* ce;

    // Search a module's configuration by its name
    for (ce = (AppidConfigElement*)sflist_first(&appid_custom_configs, &iter);
        ce != nullptr;
        ce = (AppidConfigElement*)sflist_next(&iter))
    {
        if (strcmp(ce->name, name) == 0)
        {
            snort_free(ce->name);
            snort_free(ce);
            sflist_remove_node(&appid_custom_configs, iter);
            break;
        }
    }
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
                for (; *value && *value == ' '; value++)
                    ;

                if (strcasecmp(key, "ports") == 0)
                {
                    char* context = nullptr;
                    char* ptr;
                    unsigned long tmp;

                    for (ptr = strtok_r(value, ",", &context); ptr; ptr = strtok_r(nullptr, ",",
                            &context))
                    {
                        for (; *ptr && *ptr == ' '; ptr++)
                            ;
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
                app_info_mgr.set_app_info_active(appId);
            }
            app_info_mgr.set_app_info_active(appId);
        }
        else
            ErrorMessage("Missing parameter(s) in port service '%s'\n",globs.gl_pathv[n]);

next:;
        while ((tmp_port = port))
        {
            port = tmp_port->next;
            snort_free(tmp_port);
        }
        fclose(file);
    }

    globfree(&globs);
}

void AppIdConfig::configure_analysis_networks(char* toklist[], uint32_t flag)
{
    int zone;
    NetworkSet* my_net_list;
    RNAIpAddrSet* ias;
    RNAIpv6AddrSet* ias6;
    char* p;
    long tmp;

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

                if (toklist[1])
                {
                    tmp = strtol(toklist[1], &p, 10);
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
                DebugFormat(DEBUG_APPID, "Adding %s-%s (0x%08X) with zone %d\n", min_ip, max_ip,
                    ias6->addr_flags, zone);
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
            ias = ParseIpCidr(toklist[0], app_id_netmasks);
            if (ias)
            {
                if (toklist[1])
                {
                    tmp = strtol(toklist[1], &p, 10);
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
                DebugFormat(DEBUG_APPID, "Adding 0x%08X-0x%08X (0x%08X) with zone %d\n",
                    ias->range_min, ias->range_max, ias->addr_flags, zone);
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
                if (my_net_list && NetworkSetManager::add_cidr_block_ex(my_net_list, ias->range_min,
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

int AppIdConfig::add_port_exclusion(AppIdPortExclusions& port_exclusions, const ip::snort_in6_addr* ip,
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
    RNAIpAddrSet* ias;
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
        ias = ParseIpCidr(toklist[i], app_id_netmasks);
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

int AppIdConfig::load_analysis_config(const char* config_file, int reload, int instance_id)
{
    FILE* fp;
    char linebuffer[MAX_LINE];
    char* cptr;
    char* toklist[MAX_TOKS];
    int num_toks;
    unsigned line = 0;
    NetworkSet* my_net_list;

    if (NetworkSetManager::create(&net_list))
        FatalError("Failed to allocate a network set");
    net_list_list = net_list;

    if (!config_file || (!config_file[0]))
    {
        char addrString[sizeof("0.0.0.0/0")];
        DebugMessage(DEBUG_APPID, "Defaulting to monitoring all Snort traffic for AppID.\n");
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
        DebugFormat(DEBUG_APPID, "Loading configuration file: %s", config_file);

        if (!(fp = fopen(config_file, "r")))
        {
            ErrorMessage("Unable to open %s", config_file);
            return -1;
        }

        while (fgets(linebuffer, MAX_LINE, fp) != nullptr)
        {
            line++;
            AppIdUtils::strip(linebuffer);
            cptr = linebuffer;

            while (isspace((int)*cptr))
                cptr++;

            if (*cptr && (*cptr != '#') && (*cptr != 0x0a))
            {
                memset(toklist, 0, sizeof(toklist));
                num_toks = AppIdUtils::tokenize(cptr, toklist);
                if (num_toks < 2)
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
        DebugMessage(DEBUG_APPID, "Defaulting to monitoring all Snort traffic for AppID.\n");
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
        net_list_count += NetworkSetManager::count_ex(my_net_list) + NetworkSetManager::count6_ex(my_net_list);
    }

    return 0;
}

void AppIdConfig::set_safe_search_enforcement(int enabled)
{
    DEBUG_WRAP(DebugFormat(DEBUG_APPID, "    Safe Search Enforcement enabled = %d.\n",enabled); );
    mod_config->disable_safe_search = enabled ? 0 : 1;
}

bool AppIdConfig::init_appid( )
{
    appid_config = this;
	map_app_names_to_snort_ids();
	appIdPolicyId = 53;
	AppIdUtils::init_netmasks(app_id_netmasks);
	app_info_mgr.init_appid_info_table(mod_config->app_detector_dir);
	sflist_init(&appid_config->client_app_args);
	load_analysis_config(mod_config->conf_file, 0, mod_config->instance_id);
	read_port_detectors(ODP_PORT_DETECTORS);
	read_port_detectors(CUSTOM_PORT_DETECTORS);
	ThirdPartyAppIDInit(mod_config);

	if ( mod_config->dump_ports )
	{
		dumpPorts(stdout);
		display_port_config();
		app_info_mgr.dump_app_info_table();
		exit(0);        // FIXIT-L - implement better way to dump config and exit
	}

	return true;
}

static void free_config_items(AppidConfigElement* ci)
{
    if (ci)
    {
        if (ci->name)
            snort_free(ci->name);
        if (ci->value)
            snort_free(ci->value);
        snort_free(ci);
    }
}

static void free_port_exclusion_list( AppIdPortExclusions& pe_list )
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

    if (thirdparty_appid_module != nullptr)
        thirdparty_appid_module->print_stats();
    ThirdPartyAppIDFini();

    app_info_mgr.cleanup_appid_info_table();

    NetworkSet* net_list;          ///< list of network sets
    while ((net_list = net_list_list))
    {
        net_list_list = net_list->next;
        NetworkSetManager::destroy(net_list);
    }

    free_port_exclusion_list(tcp_port_exclusions_src);
    free_port_exclusion_list(tcp_port_exclusions_dst);
    free_port_exclusion_list(udp_port_exclusions_src);
    free_port_exclusion_list(udp_port_exclusions_dst);

    sflist_static_free_all(&client_app_args, (void (*)(void*))free_config_items);
}

static void display_port_exclusion_list(SF_LIST* pe_list, uint16_t port)
{
    const char* p;
    const char* p2;
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
        p = inet_ntop(pe->family, &pe->ip, inet_buffer, sizeof(inet_buffer));
        p2 = inet_ntop(pe->family, &pe->netmask, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %d on %s/%s\n", port, p ? p : "ERROR", p2 ? p2 : "ERROR");
    }
}

void AppIdConfig::show()
{
    unsigned i;
    int j;
    struct in_addr ia;
    char inet_buffer[INET6_ADDRSTRLEN];
    char inet_buffer2[INET6_ADDRSTRLEN];
    NSIPv6Addr six;
    const char* p;
    const char* p2;
    NetworkSet* my_net_list;

    if (mod_config->thirdparty_appid_dir)
        LogMessage("    3rd Party Dir: %s\n", mod_config->thirdparty_appid_dir);

    my_net_list = net_list;
    LogMessage("    Monitoring Networks for any zone:\n");
    for (i = 0; i < my_net_list->count; i++)
    {
        ia.s_addr = htonl(my_net_list->pnetwork[i]->range_min);
        p = inet_ntop(AF_INET, &ia, inet_buffer, sizeof(inet_buffer));
        ia.s_addr = htonl(my_net_list->pnetwork[i]->range_max);
        p2 = inet_ntop(AF_INET, &ia, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %s%s-%s %04X\n", (my_net_list->pnetwork[i]->info.ip_not) ? "!" : "",
            p ?
            p : "ERROR",
            p2 ? p2 : "ERROR", my_net_list->pnetwork[i]->info.type);
    }
    for (i = 0; i < my_net_list->count6; i++)
    {
        six = my_net_list->pnetwork6[i]->range_min;
        NetworkSetManager::ntoh_ipv6(&six);
        p = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer, sizeof(inet_buffer));
        six = my_net_list->pnetwork6[i]->range_max;
        NetworkSetManager::ntoh_ipv6(&six);
        p2 = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer2, sizeof(inet_buffer2));
        LogMessage("        %s%s-%s %04X\n", (my_net_list->pnetwork6[i]->info.ip_not) ? "!" : "",
            p ?
            p : "ERROR",
            p2 ? p2 : "ERROR", my_net_list->pnetwork6[i]->info.type);
    }

    for (j=0; j < MAX_ZONES; j++)
    {
        if (!(my_net_list = net_list_by_zone[j]))
            continue;
        LogMessage("    Monitoring Networks for zone %d:\n", j);
        for (i = 0; i < my_net_list->count; i++)
        {
            ia.s_addr = htonl(my_net_list->pnetwork[i]->range_min);
            p = inet_ntop(AF_INET, &ia, inet_buffer, sizeof(inet_buffer));
            ia.s_addr = htonl(my_net_list->pnetwork[i]->range_max);
            p2 = inet_ntop(AF_INET, &ia, inet_buffer2, sizeof(inet_buffer2));
            LogMessage("        %s%s-%s %04X\n", (my_net_list->pnetwork[i]->info.ip_not) ? "!" :
                "",
                p ? p : "ERROR",
                p2 ? p2 : "ERROR", my_net_list->pnetwork[i]->info.type);
        }
        for (i = 0; i < my_net_list->count6; i++)
        {
            six = my_net_list->pnetwork6[i]->range_min;
            NetworkSetManager::ntoh_ipv6(&six);
            p = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer, sizeof(inet_buffer));
            six = my_net_list->pnetwork6[i]->range_max;
            NetworkSetManager::ntoh_ipv6(&six);
            p2 = inet_ntop(AF_INET6, (struct in6_addr*)&six, inet_buffer2, sizeof(inet_buffer2));
            LogMessage("        %s%s-%s %04X\n", (my_net_list->pnetwork6[i]->info.ip_not) ? "!" :
                "",
                p ? p : "ERROR",
                p2 ? p2 : "ERROR", my_net_list->pnetwork6[i]->info.type);
        }
    }

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
