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

// client_app_base.cc author Ron Dempster <Ron.Dempster@sourcefire.com>

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "client_app_base.h"

#include "main/snort_debug.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"
#include "profiler/profiler.h"

#include "appid_api.h"
#include "appid_config.h"
#include "fw_appid.h"
#include "client_app_api.h"
#include "client_app_base.h"
#include "client_app_smtp.h"
#include "client_app_msn.h"
#include "client_app_aim.h"
#include "client_app_ym.h"
#include "detector_plugins/detector_sip.h"
#include "lua_detector_module.h"
#include "lua_detector_api.h"
#include "http_common.h"
#include "service_plugins/service_ssl.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/detector_pattern.h"

/*#define CLIENT_APP_DEBUG    1 */

#define BUFSIZE         512

/* If this is greater than 1, more than 1 client detector can be searched for
 * and tried per flow based on pattern (if a valid detector doesn't
 * already exist). */
#define MAX_CANDIDATE_CLIENTS 10

static void* client_app_flowdata_get(AppIdData* flowp, unsigned client_id);
static int client_app_flowdata_add(AppIdData* flowp, void* data, unsigned client_id, AppIdFreeFCN
    fcn);
static void AppIdAddClientAppInfo(AppIdData* flowp, const char* info);

static const ClientAppApi client_app_api =
{
    &client_app_flowdata_get,
    &client_app_flowdata_add,
    &AppIdAddClientApp,
    &AppIdAddClientAppInfo,
    &AppIdAddUser,
    &AppIdAddPayload
};

static void LuaClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size,
    int position, struct Detector* userData);
static void CClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size,
    int position, AppIdConfig* pConfig);
static void CClientAppRegisterPatternNoCase(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size,
    int position, AppIdConfig* pConfig);

static IniClientAppAPI client_init_api =
{
    &CClientAppRegisterPattern,
    &LuaClientAppRegisterPattern,
    &CClientAppRegisterPatternNoCase,
    &appSetClientValidator,
    0,
    0,
    nullptr
};

static CleanClientAppAPI clean_api =
{
};

static FinalizeClientAppAPI finalize_api =
{
};

extern RNAClientAppModule bit_client_mod;
extern RNAClientAppModule bit_tracker_client_mod;
extern RNAClientAppModule rtp_client_mod;
extern RNAClientAppModule ssh_client_mod;
extern RNAClientAppModule timbuktu_client_mod;
extern RNAClientAppModule tns_client_mod;
extern RNAClientAppModule vnc_client_mod;
extern RNAClientAppModule pattern_udp_client_mod;
extern RNAClientAppModule pattern_tcp_client_mod;
extern RNAClientAppModule http_client_mod;

static RNAClientAppModule* static_client_list[] =
{
    &smtp_client_mod,

#ifdef REMOVED_WHILE_NOT_IN_USE
    &msn_client_mod,
    &aim_client_mod,
    &ym_client_mod,
    &sip_udp_client_mod,
    &sip_tcp_client_mod,
    &bit_client_mod,
    &bit_tracker_client_mod,
    &rtp_client_mod,
    &ssh_client_mod,
    &timbuktu_client_mod,
    &tns_client_mod,
    &vnc_client_mod,
    &pattern_udp_client_mod,
    &pattern_tcp_client_mod,
#endif
    &dns_udp_client_mod,
    &dns_tcp_client_mod,
    &http_client_mod
};

/*static const char * const MODULE_NAME = "ClientApp"; */

const ClientAppApi* getClientApi(void)
{
    return &client_app_api;
}

RNAClientAppModuleConfig* geClientAppModuleConfig(const char* moduleName,
    ClientAppConfig* pClientAppConfig)
{
    SF_LNODE* cursor;
    RNAClientAppModuleConfig* mod_config;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&pClientAppConfig->module_configs,
            &cursor);
        mod_config;
        mod_config = (RNAClientAppModuleConfig*)sflist_next(&cursor))
    {
        if (strcasecmp(mod_config->name, moduleName) == 0)
            break;
    }
    return mod_config;
}

const RNAClientAppModule* ClientAppGetClientAppModule(RNAClientAppFCN fcn, struct
    Detector* userdata,
    ClientAppConfig* pClientAppConfig)
{
    RNAClientAppRecord* li;

    for (li = pClientAppConfig->tcp_client_app_list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userdata))
            return li->module;
    }
    for (li=pClientAppConfig->udp_client_app_list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userdata))
            return li->module;
    }
    return nullptr;
}

void add_pattern_data(SearchTool* st, const RNAClientAppModule* li, int position, const
    uint8_t* const pattern, unsigned size,
    unsigned nocase, int* count, ClientAppConfig* pClientAppConfig)
{
    ClientPatternData* pd = (ClientPatternData*)snort_calloc(sizeof(ClientPatternData));
    pd->ca = li;
    pd->position = position;
    (*count)++;
    pd->next = pClientAppConfig->pattern_data_list;
    pClientAppConfig->pattern_data_list = pd;
    st->add((const char*)pattern, size, pd, nocase);
}

static void clientCreatePattern(IpProtocol proto, const uint8_t* const pattern, unsigned size,
    int position, unsigned nocase, const RNAClientAppModule* li, ClientAppConfig* pClientAppConfig)
{
    int* count;

    if (!li)
    {
        ErrorMessage("Invalid client app when registering a pattern");
        return;
    }

    if (proto == IpProtocol::TCP)
    {
        if (pClientAppConfig->tcp_patterns)
            delete pClientAppConfig->tcp_patterns;
        pClientAppConfig->tcp_patterns = new SearchTool("ac_full");
        pClientAppConfig->udp_patterns = nullptr;
        count = &pClientAppConfig->tcp_pattern_count;
        add_pattern_data(pClientAppConfig->tcp_patterns, li, position, pattern, size,
            nocase, count, pClientAppConfig);
    }
    else if (proto == IpProtocol::UDP)
    {
        if (pClientAppConfig->udp_patterns)
            delete pClientAppConfig->udp_patterns;
        pClientAppConfig->udp_patterns = new SearchTool("ac_full");
        pClientAppConfig->tcp_patterns = nullptr;
        count = &pClientAppConfig->udp_pattern_count;
        add_pattern_data(pClientAppConfig->udp_patterns, li, position, pattern, size,
            nocase, count, pClientAppConfig);
    }
    else
    {
        pClientAppConfig->tcp_patterns = nullptr;
        pClientAppConfig->udp_patterns = nullptr;
        ErrorMessage("Invalid protocol when registering a pattern: %u\n",(unsigned)proto);
    }
}

static void CClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size,
    int position, AppIdConfig* pConfig)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 0, nullptr,
        &pConfig->clientAppConfig);
}

static void CClientAppRegisterPatternNoCase(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size,
    int position, AppIdConfig* pConfig)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 1, nullptr,
        &pConfig->clientAppConfig);
}

static void LuaClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position, struct Detector* userData)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 0, userData,
        &userData->pAppidNewConfig->clientAppConfig);
}

void ClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase, struct Detector* userData,
    ClientAppConfig* pClientAppConfig)
{
    RNAClientAppRecord* list;
    RNAClientAppRecord* li;

    if (proto == IpProtocol::TCP)
        list = pClientAppConfig->tcp_client_app_list;
    else if (proto == IpProtocol::UDP)
        list = pClientAppConfig->udp_client_app_list;
    else
    {
        ErrorMessage("Invalid protocol when registering a pattern: %u\n",(unsigned)proto);
        return;
    }

    for (li=list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userData))
        {
            clientCreatePattern(proto, pattern, size, position, nocase, li->module,
                pClientAppConfig);
            break;
        }
    }
}

int ClientAppLoadForConfigCallback(void* symbol, ClientAppConfig* pClientAppConfig)
{
    static unsigned client_module_index = 0;
    RNAClientAppModule* cam = (RNAClientAppModule*)symbol;
    RNAClientAppRecord** list = nullptr;
    RNAClientAppRecord* li;

    DebugFormat(DEBUG_LOG,"Adding client %s for protocol %u\n",cam->name, (unsigned)cam->proto);

    if (client_module_index >= 65536)
    {
        ErrorMessage("Maximum number of client modules exceeded");
        return -1;
    }

    if (cam->proto == IpProtocol::TCP)
    {
        list = &pClientAppConfig->tcp_client_app_list;
    }
    else if (cam->proto == IpProtocol::UDP)
    {
        list = &pClientAppConfig->udp_client_app_list;
    }
    else
    {
        ErrorMessage("Client %s did not have a valid protocol (%u)",
            cam->name, (unsigned)cam->proto);
        return -1;
    }

    for (li = *list; li; li=li->next)
    {
        if (li->module == cam)
            break;
    }
    if (!li)
    {
        li = (RNAClientAppRecord*)snort_calloc(sizeof(RNAClientAppRecord));
        li->next = *list;
        *list = li;
        li->module = cam;
        cam->api = &client_app_api;
        cam->flow_data_index = client_module_index | APPID_SESSION_DATA_CLIENT_MODSTATE_BIT;
        client_module_index++;
    }
    /*Can't set cam->userData to nullptr because Lua detectors use it although C detectors don't
      cam->userData = nullptr; */
    return 0;
}

int ClientAppLoadCallback(void* symbol)
{
    return ClientAppLoadForConfigCallback(symbol, &pAppidActiveConfig->clientAppConfig);
}

int LoadClientAppModules(AppIdConfig* pConfig)
{
    unsigned i;

    for (i=0; i<sizeof(static_client_list)/sizeof(*static_client_list); i++)
    {
        if (ClientAppLoadForConfigCallback(static_client_list[i], &pConfig->clientAppConfig))
            return -1;
    }

    return 0;
}

static void AddModuleConfigItem(char* module_name, char* item_name, char* item_value,
    ClientAppConfig* config)
{
    SF_LNODE* cursor;
    RNAClientAppModuleConfig* mod_config;
    RNAClientAppModuleConfigItem* item;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&config->module_configs, &cursor);
        mod_config;
        mod_config = (RNAClientAppModuleConfig*)sflist_next(&cursor))
    {
        if (strcasecmp(mod_config->name, module_name) == 0)
            break;
    }

    if (!mod_config)
    {
        mod_config = (RNAClientAppModuleConfig*)snort_calloc(sizeof(RNAClientAppModuleConfig));
        mod_config->name = snort_strdup(module_name);
        sflist_init(&mod_config->items);
        if (sflist_add_tail(&config->module_configs, mod_config))
        {
            ErrorMessage("Failed to add a module configuration");
            exit(-1);
        }
    }

    for (item = (RNAClientAppModuleConfigItem*)sflist_first(&mod_config->items, &cursor);
        item;
        item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
    {
        if (strcasecmp(item->name, item_name) == 0)
            break;
    }

    if (!item)
    {
        item = (RNAClientAppModuleConfigItem*)snort_calloc(sizeof(RNAClientAppModuleConfigItem));
        item->name = snort_strdup(item_name);
        if (sflist_add_tail(&mod_config->items, item))
        {
            ErrorMessage("Failed to add a module configuration item");
            exit(-1);
        }
    }

    if (item->value)
        snort_free((void*)item->value);

    item->value = snort_strdup(item_value);
}

static void ClientAppParseOption(ClientAppConfig* config,
    char* key, char* value)
{
    char* p;

    if (!strcasecmp(key, "enable"))
    {
        config->enabled = atoi(value);
    }
    else if ((p = strchr(key, ':')) && p[1])
    {
        *p = 0;
        AddModuleConfigItem(key, &p[1], value, config);
        *p = ':';
    }
    else
    {
        DebugFormat(DEBUG_LOG, "Unknown client app argument ignored: key(%s) value(%s)",
            key, value);
    }
}

#ifdef DEBUG
#define MAX_DISPLAY_SIZE   65536
static void DisplayClientAppConfig(ClientAppConfig* config)
{
    static char buffer[MAX_DISPLAY_SIZE];
    int position = 0;
    int tmp;

    RNAClientAppModuleConfig* mod_config;
    RNAClientAppModuleConfigItem* item;
    SF_LNODE* cursor;

    tmp = snprintf(&buffer[position], MAX_DISPLAY_SIZE-position,
        "\n----------------------------------------------\nRNA Client App Config\n");
    if (tmp >= MAX_DISPLAY_SIZE-position)
        position = MAX_DISPLAY_SIZE;
    else if (tmp > 0)
        position += tmp;

    tmp = snprintf(&buffer[position], MAX_DISPLAY_SIZE-position,
        "Enabled: %s\n", config->enabled ? "Yes" : "No");
    if (tmp >= MAX_DISPLAY_SIZE-position)
        position = MAX_DISPLAY_SIZE;
    else if (tmp > 0)
        position += tmp;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&config->module_configs, &cursor);
        mod_config;
        mod_config = (RNAClientAppModuleConfig*)sflist_next(&cursor))
    {
        SF_LNODE* cursor;

        tmp = snprintf(&buffer[position], MAX_DISPLAY_SIZE-position, "%s\n", mod_config->name);
        if (tmp >= MAX_DISPLAY_SIZE-position)
            position = MAX_DISPLAY_SIZE;
        else if (tmp > 0)
            position += tmp;

        for (item = (RNAClientAppModuleConfigItem*)sflist_first(&mod_config->items, &cursor);
            item;
            item = (RNAClientAppModuleConfigItem*)sflist_next(&cursor))
        {
            tmp = snprintf(&buffer[position], MAX_DISPLAY_SIZE-position,
                "   %s: %s\n", item->name, item->value);
            if (tmp >= MAX_DISPLAY_SIZE-position)
                position = MAX_DISPLAY_SIZE;
            else if (tmp > 0)
                position += tmp;
        }
    }

    snprintf(&buffer[position], MAX_DISPLAY_SIZE - position,
        "----------------------------------------------\n");
    DebugFormat(DEBUG_LOG,"%s\n",buffer);
}
#endif

static int ClientAppParseArgs(ClientAppConfig* config, SF_LIST* args)
{
    ConfigItem* ci;
    SF_LNODE* cursor;

    for (ci = (ConfigItem*)sflist_first(args, &cursor);
        ci;
        ci = (ConfigItem*)sflist_next(&cursor))
    {
        ClientAppParseOption(config, ci->name, ci->value);
    }

#ifdef DEBUG
    DisplayClientAppConfig(config);
#endif
    return 0;
}


static void free_module_config_item(void* module_config_item)
{
    RNAClientAppModuleConfigItem* item = (RNAClientAppModuleConfigItem*)module_config_item;

    if (item)
    {
        if (item->name)
            snort_free((void*)item->name);
        if (item->value)
            snort_free((void*)item->value);
        snort_free(item);
    }
}

static void free_module_config(void* module_config)
{
    RNAClientAppModuleConfig* config = (RNAClientAppModuleConfig*)module_config;
    if (config)
    {
        if (config->name)
            snort_free((void*)config->name);
        sflist_static_free_all(&config->items, &free_module_config_item);
        snort_free(config);
    }
}

static void initialize_module(RNAClientAppRecord* li, ClientAppConfig* pClientAppConfig)
{
    RNAClientAppModuleConfig* mod_config;
    SF_LNODE* cursor;
    int rval;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&pClientAppConfig->module_configs,
            &cursor);
        mod_config;
        mod_config = (RNAClientAppModuleConfig*)sflist_next(&cursor))
    {
        if (strcasecmp(mod_config->name, li->module->name) == 0)
            break;
    }
    if (li->module->init && (rval=li->module->init(&client_init_api, mod_config ?
            &mod_config->items : nullptr)) != CLIENT_APP_SUCCESS)
    {
        ErrorMessage("Could not initialize the %s client app element: %d\n",li->module->name,
            rval);
        exit(-1);
    }
}

static void finalize_module(RNAClientAppRecord* li)
{
    int rval;

    if ( li->module->finalize && ( rval = (li->module->finalize)(&finalize_api) ) !=
        CLIENT_APP_SUCCESS )
    {
        ErrorMessage("Could not finlize the %s client app element: %d\n",li->module->name, rval);
        exit(-1);
    }
}

static void clean_module(RNAClientAppRecord* li)
{
    if (li->module->clean)
        li->module->clean(&clean_api);
}

void UnconfigureClientApp(AppIdConfig* pConfig)
{
    ClientPatternData* pd;
    RNAClientAppRecord* li;

    clean_api.pAppidConfig = pConfig;
    for (li = pConfig->clientAppConfig.tcp_client_app_list; li; li = li->next)
        clean_module(li);
    for (li = pConfig->clientAppConfig.udp_client_app_list; li; li = li->next)
        clean_module(li);

    // FIXIT - should this be deleted here? or move this clean up to a dtor?
    delete pConfig->clientAppConfig.tcp_patterns;
    pConfig->clientAppConfig.tcp_patterns = nullptr;

    delete pConfig->clientAppConfig.udp_patterns;
    pConfig->clientAppConfig.udp_patterns = nullptr;

    while (pConfig->clientAppConfig.pattern_data_list)
    {
        pd = pConfig->clientAppConfig.pattern_data_list;
        pConfig->clientAppConfig.pattern_data_list = pd->next;
        snort_free((void*)pd);
    }

    CleanHttpPatternLists(pConfig);
#ifdef REMOVED_WHILE_NOT_IN_USE
    ssl_detector_free_patterns(&pConfig->serviceSslConfig);
#endif
    dns_detector_free_patterns(&pConfig->serviceDnsConfig);
    CleanClientPortPatternList(pConfig);

    sflist_static_free_all(&pConfig->clientAppConfig.module_configs, &free_module_config);
}

/**
 * Initialize the configuration of the client app module
 *
 * @param args
 */
void ClientAppInit(AppIdConfig* pConfig)
{
    RNAClientAppRecord* li;

    sflist_init(&pConfig->clientAppConfig.module_configs);
    pConfig->clientAppConfig.enabled = 1;

    ClientAppParseArgs(&pConfig->clientAppConfig, &pConfig->client_app_args);

    if (pConfig->clientAppConfig.enabled)
    {
        client_init_api.debug = app_id_debug;
        client_init_api.pAppidConfig = pConfig;
        // FIXIT - active config global must go...
        client_init_api.instance_id = pAppidActiveConfig->mod_config->instance_id;

        for (li = pConfig->clientAppConfig.tcp_client_app_list; li; li = li->next)
            initialize_module(li, &pConfig->clientAppConfig);
        for (li = pConfig->clientAppConfig.udp_client_app_list; li; li = li->next)
            initialize_module(li, &pConfig->clientAppConfig);

        luaModuleInitAllClients();

        for (li = pConfig->clientAppConfig.tcp_client_app_list; li; li = li->next)
            finalize_module(li);

        for (li = pConfig->clientAppConfig.udp_client_app_list; li; li = li->next)
            finalize_module(li);
    }
}

void ClientAppFinalize(AppIdConfig* pConfig)
{
    if (pConfig->clientAppConfig.enabled)
    {
        if ( pConfig->clientAppConfig.tcp_patterns )
            pConfig->clientAppConfig.tcp_patterns->prep();

        if ( pConfig->clientAppConfig.udp_patterns )
            pConfig->clientAppConfig.udp_patterns->prep();
    }
}

struct ClientAppMatch
{
    struct ClientAppMatch* next;
    unsigned count;
    const RNAClientAppModule* ca;
};

static ClientAppMatch* match_free_list;

/**
 * Clean up the configuration of the client app module
 */
void CleanupClientApp(AppIdConfig* /* pConfig */)
{
#ifdef RNA_FULL_CLEANUP
    ClientAppMatch* match;
    ClientPatternData* pd;
    RNAClientAppRecord* li;

    clean_api.pAppidConfig = pConfig;
    if (pConfig->clientAppConfig.tcp_patterns)
    {
        delete pConfig->clientAppConfig.tcp_patterns;
        pConfig->clientAppConfig.tcp_patterns = nullptr;
    }
    if (pConfig->clientAppConfig.udp_patterns)
    {
        delete pConfig->clientAppConfig.udp_patterns;
        pConfig->clientAppConfig.udp_patterns = nullptr;
    }
    while ((pd = pConfig->clientAppConfig.pattern_data_list) != nullptr)
    {
        pConfig->clientAppConfig.pattern_data_list = pd->next;
        snort_free(pd);
    }

    while ((li=pConfig->clientAppConfig.tcp_client_app_list) != nullptr)
    {
        pConfig->clientAppConfig.tcp_client_app_list = li->next;
        if (li->module->clean)
            li->module->clean(&clean_api);
        snort_free(li);
    }
    while ((li=pConfig->clientAppConfig.udp_client_app_list) != nullptr)
    {
        pConfig->clientAppConfig.udp_client_app_list = li->next;
        if (li->module->clean)
            li->module->clean(&clean_api);
        snort_free(li);
    }

    luaModuleCleanAllClients();

    CleanHttpPatternLists(pConfig);
    ssl_detector_free_patterns(&pConfig->serviceSslConfig);
    dns_detector_free_patterns(&pConfig->serviceDnsConfig);
    CleanClientPortPatternList(pConfig);

    sflist_static_free_all(&pConfig->clientAppConfig.module_configs, &free_module_config);
    while ((match=match_free_list) != nullptr)
    {
        match_free_list = match->next;
        snort_free(match);
    }
#endif
}

/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from pop_config.cmds
 * @param   index   index in array of search strings from pop_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int pattern_match(void* id, void* /*unused_tree*/, int index, void* data,
    void* /*unused_neg*/)
{
    ClientAppMatch** matches = (ClientAppMatch**)data;
    ClientPatternData* pd = (ClientPatternData*)id;
    ClientAppMatch* cam;

    if ( pd->position >= 0 && pd->position != index )
        return 0;

    for (cam = *matches; cam; cam = cam->next)
    {
        if (cam->ca == pd->ca)
            break;
    }

    if (cam)
        cam->count++;
    else
    {
        if (match_free_list)
        {
            cam = match_free_list;
            match_free_list = cam->next;
            memset(cam, 0, sizeof(*cam));
        }
        else
            cam = (ClientAppMatch*)snort_calloc(sizeof(ClientAppMatch));

        cam->count = 1;
        cam->ca = pd->ca;
        cam->next = *matches;
        *matches = cam;
    }
    return 0;
}

void AppIdAddClientApp(AppIdData* flowp, AppId service_id, AppId id, const char* version)
{
    if (version)
    {
        if (flowp->clientVersion)
        {
            if (strcmp(version, flowp->clientVersion))
            {
                snort_free(flowp->clientVersion);
                flowp->clientVersion = snort_strdup(version);
            }
        }
        else
            flowp->clientVersion = snort_strdup(version);
    }

    setAppIdFlag(flowp, APPID_SESSION_CLIENT_DETECTED);
    flowp->ClientServiceAppId = service_id;
    flowp->ClientAppId = id;
    checkSandboxDetection(id);
}

static void AppIdAddClientAppInfo(AppIdData* flowp, const char* info)
{
    if (flowp->hsession && !flowp->hsession->url)
        flowp->hsession->url = snort_strdup(info);
}

static ClientAppMatch* BuildClientPatternList(const Packet* pkt, IpProtocol protocol,
    const ClientAppConfig* pClientAppConfig)
{
    ClientAppMatch* match_list = nullptr;
    SearchTool* patterns;

    if (protocol == IpProtocol::TCP)
        patterns = pClientAppConfig->tcp_patterns;
    else
        patterns = pClientAppConfig->udp_patterns;

    if (!patterns)
        return nullptr;

    patterns->find_all((char*)pkt->data, pkt->dsize, &pattern_match, false, (void*)&match_list);

    return match_list;
}

static const RNAClientAppModule* GetNextFromClientPatternList(ClientAppMatch** match_list)
{
    ClientAppMatch* curr = nullptr;
    ClientAppMatch* prev = nullptr;
    ClientAppMatch* max_curr = nullptr;
    ClientAppMatch* max_prev = nullptr;
    unsigned max_count;
    unsigned max_precedence;

    curr = *match_list;
    max_count = 0;
    max_precedence = 0;
    while (curr)
    {
        if (curr->count >= curr->ca->minimum_matches
            && ((curr->count > max_count)
            || (curr->count == max_count && curr->ca->precedence > max_precedence)))
        {
            max_count = curr->count;
            max_precedence = curr->ca->precedence;
            max_curr = curr;
            max_prev = prev;
        }
        prev = curr;
        curr = curr->next;
    }

    if (max_curr != nullptr)
    {
        if (max_prev == nullptr)
        {
            *match_list = (*match_list)->next;
        }
        else
        {
            max_prev->next = max_curr->next;
        }
        max_curr->next = match_free_list;
        match_free_list = max_curr;
        return max_curr->ca;
    }
    else
    {
        return nullptr;
    }
}

static void FreeClientPatternList(ClientAppMatch** match_list)
{
    ClientAppMatch* cam;
    ClientAppMatch* tmp;

    cam = *match_list;
    while (cam)
    {
        tmp = cam;
        cam = tmp->next;
        tmp->next = match_free_list;
        match_free_list = tmp;
    }

    *match_list = nullptr;
}

/**
 * The process to determine the running client app given the packet data.
 *
 * @param p packet to process
 */
static void ClientAppID(Packet* p, const int /*direction*/, AppIdData* flowp, const
    AppIdConfig* pConfig)
{
    const RNAClientAppModule* client = nullptr;
    ClientAppMatch* match_list;

#ifdef CLIENT_APP_DEBUG
    _dpd.logMsg("Client");
#endif

    if (!p->dsize)
        return;

    if (flowp->clientData != nullptr)
        return;

    if (flowp->candidate_client_list != nullptr)
    {
        if (flowp->num_candidate_clients_tried > 0)
            return;
    }
    else
    {
        flowp->candidate_client_list = (SF_LIST*) snort_calloc(sizeof(SF_LIST));
        sflist_init(flowp->candidate_client_list);
        flowp->num_candidate_clients_tried = 0;
    }

    match_list = BuildClientPatternList(p, flowp->proto, &pConfig->clientAppConfig);
    while (flowp->num_candidate_clients_tried < MAX_CANDIDATE_CLIENTS)
    {
        const RNAClientAppModule* tmp = GetNextFromClientPatternList(&match_list);
        if (tmp != nullptr)
        {
            SF_LNODE* cursor;

            client = (RNAClientAppModule*)sflist_first(flowp->candidate_client_list, &cursor);
            while (client && (client != tmp))
                client = (RNAClientAppModule*)sflist_next(&cursor);
            if (client == nullptr)
            {
                sflist_add_tail(flowp->candidate_client_list, (void*)tmp);
                flowp->num_candidate_clients_tried++;
#ifdef CLIENT_APP_DEBUG
                _dpd.logMsg("Using %s from pattern match", tmp ? tmp->name : \ n ",ULL");
#endif
            }
        }
        else
        {
            break;
        }
    }
    FreeClientPatternList(&match_list);

    if (sflist_count(flowp->candidate_client_list) == 0)
    {
        client = nullptr;
        switch (p->ptrs.dp)
        {
        case 465:
            if (getAppIdFlag(flowp, APPID_SESSION_DECRYPTED))
                client = &smtp_client_mod;
            break;
        default:
            break;
        }
        if (client != nullptr)
        {
            sflist_add_tail(flowp->candidate_client_list, (void*)client);
            flowp->num_candidate_clients_tried++;
        }
    }
}

int AppIdDiscoverClientApp(Packet* p, int direction, AppIdData* rnaData, const
    AppIdConfig* pConfig)
{
    if (!pConfig->clientAppConfig.enabled)
        return APPID_SESSION_SUCCESS;

    if (direction == APP_ID_FROM_INITIATOR)
    {
        /* get out if we've already tried to validate a client app */
        if (!getAppIdFlag(rnaData, APPID_SESSION_CLIENT_DETECTED))
            ClientAppID(p, direction, rnaData, pConfig);
    }
    else if (rnaData->rnaServiceState != RNA_STATE_STATEFUL && getAppIdFlag(rnaData,
        APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
        ClientAppID(p, direction, rnaData, pConfig);

    return APPID_SESSION_SUCCESS;
}

DetectorAppUrlList* geAppUrlList(AppIdConfig* pConfig)
{
    HttpPatternLists* patternLists = &pConfig->httpPatternLists;
    return (&patternLists->appUrlList);
}

static void* client_app_flowdata_get(AppIdData* flowp, unsigned client_id)
{
    return AppIdFlowdataGet(flowp, client_id);
}

static int client_app_flowdata_add(AppIdData* flowp, void* data, unsigned client_id, AppIdFreeFCN
    fcn)
{
    return AppIdFlowdataAdd(flowp, data, client_id, fcn);
}

