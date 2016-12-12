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

#include "client_app_base.h"

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main/snort_debug.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "utils/sflsq.h"
#include "utils/util.h"
#include "profiler/profiler.h"

#include "appid_api.h"
#include "appid_config.h"
#include "app_info_table.h"
#include "client_app_api.h"
#include "client_app_base.h"
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

static void* client_app_flowdata_get(AppIdSession* asd, unsigned client_id);
static int client_app_flowdata_add(AppIdSession* asd, void* data, unsigned client_id, AppIdFreeFCN
    fcn);
static void AppIdAddClientAppInfo(AppIdSession* asd, const char* info);

static const ClientAppApi client_app_api =
{
    &client_app_flowdata_get,
    &client_app_flowdata_add,
    &AppIdAddClientApp,
    &AppIdAddClientAppInfo,
    &AppIdSession::add_user,
    &AppIdSession::add_payload
};

static void CClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position);
static void LuaClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position, Detector* userData);
static void CClientAppRegisterPatternNoCase(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position);
static void appSetClientValidator(RNAClientAppFCN fcn, AppId appId, unsigned extractsInfo);

static InitClientAppAPI client_init_api =
{
    &CClientAppRegisterPattern,
    &LuaClientAppRegisterPattern,
    &CClientAppRegisterPatternNoCase,
    &appSetClientValidator,
    0,
    0,
    nullptr
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

static RNAClientAppModule* builtin_client_plugins[] =
{
    &ssh_client_mod,
    &msn_client_mod,
    &aim_client_mod,
    &ym_client_mod,
    &sip_udp_client_mod,
    &sip_tcp_client_mod,
    &bit_client_mod,
    &bit_tracker_client_mod,
    &rtp_client_mod,
    &timbuktu_client_mod,
    &tns_client_mod,
    &vnc_client_mod,
    &pattern_udp_client_mod,
    &pattern_tcp_client_mod,
    &dns_udp_client_mod,
    &dns_tcp_client_mod,
    &http_client_mod
};
const uint32_t NUM_BUILTIN_CLIENT_PLUGINS =  sizeof(builtin_client_plugins)/sizeof(RNAClientAppModule*);

static THREAD_LOCAL ClientAppConfig* client_app_config = nullptr;

struct ClientAppMatch
{
    struct ClientAppMatch* next;
    unsigned count;
    const RNAClientAppModule* ca;
};

static THREAD_LOCAL ClientAppMatch* match_free_list = nullptr;

static void appSetClientValidator(RNAClientAppFCN fcn, AppId appId, unsigned extractsInfo)
{
    AppInfoTableEntry* pEntry = AppInfoManager::get_instance().get_app_info_entry(appId);
    if (!pEntry)
    {
        ParseWarning(WARN_RULES,
            "AppId: ID to Name mapping entry missing for AppId: %d. No rule support for this ID.",
            appId);
        return;
    }
    extractsInfo &= (APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER);
    if (!extractsInfo)
    {
        DebugFormat(DEBUG_LOG,
            "Ignoring direct client application without info for AppId: %d", appId);
        return;
    }
    pEntry->clntValidator = ClientAppGetClientAppModule(fcn, nullptr);
    if (pEntry->clntValidator)
        pEntry->flags |= extractsInfo;
    else
        ErrorMessage("Appid: Failed to find a client application module for AppId: %d\n", appId);
}

const ClientAppApi* getClientApi(void)
{
    return &client_app_api;
}

RNAClientAppModuleConfig* getClientAppModuleConfig(const char* moduleName)
{
    SF_LNODE* cursor;
    RNAClientAppModuleConfig* mod_config;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&client_app_config->module_configs,
            &cursor);
        mod_config;
        mod_config = (RNAClientAppModuleConfig*)sflist_next(&cursor))
    {
        if (strcasecmp(mod_config->name, moduleName) == 0)
            break;
    }
    return mod_config;
}

const RNAClientAppModule* ClientAppGetClientAppModule(RNAClientAppFCN fcn, Detector* userdata)
{
    RNAClientAppRecord* li;

    for (li = client_app_config->tcp_client_app_list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userdata))
            return li->module;
    }
    for (li=client_app_config->udp_client_app_list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userdata))
            return li->module;
    }
    return nullptr;
}

static void add_pattern_data(SearchTool* st, const RNAClientAppModule* li, int position,
        const uint8_t* const pattern, unsigned size, unsigned nocase, int* count)
{
    ClientPatternData* pd = (ClientPatternData*)snort_calloc(sizeof(ClientPatternData));
    pd->ca = li;
    pd->position = position;
    (*count)++;
    pd->next = client_app_config->pattern_data_list;
    client_app_config->pattern_data_list = pd;
    st->add((const char*)pattern, size, pd, nocase);
}

static void clientCreatePattern(IpProtocol proto, const uint8_t* const pattern, unsigned size,
    int position, unsigned nocase, const RNAClientAppModule* li)
{
    int* count;

    if (!li)
    {
        ErrorMessage("Invalid client app when registering a pattern");
        return;
    }

    if (proto == IpProtocol::TCP)
    {
        if (!client_app_config->tcp_patterns)
            client_app_config->tcp_patterns = new SearchTool("ac_full");
        count = &client_app_config->tcp_pattern_count;
        add_pattern_data(client_app_config->tcp_patterns, li, position, pattern, size, nocase, count);
    }
    else if (proto == IpProtocol::UDP)
    {
        if (!client_app_config->udp_patterns)
            client_app_config->udp_patterns = new SearchTool("ac_full");
        count = &client_app_config->udp_pattern_count;
        add_pattern_data(client_app_config->udp_patterns, li, position, pattern, size, nocase, count);
    }
    else
    {
        ErrorMessage("Invalid protocol when registering a pattern: %u\n",(unsigned)proto);
    }
}

static void CClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 0, nullptr);
}

static void CClientAppRegisterPatternNoCase(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 1, nullptr);
}

static void LuaClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto,
    const uint8_t* const pattern, unsigned size, int position, Detector* userData)
{
    ClientAppRegisterPattern(fcn, proto, pattern, size, position, 0, userData);
}

void ClientAppRegisterPattern(RNAClientAppFCN fcn, IpProtocol proto, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase, Detector* userData)
{
    RNAClientAppRecord* list;
    RNAClientAppRecord* li;

    if (proto == IpProtocol::TCP)
        list = client_app_config->tcp_client_app_list;
    else if (proto == IpProtocol::UDP)
        list = client_app_config->udp_client_app_list;
    else
    {
        ErrorMessage("Invalid protocol when registering a pattern: %u\n",(unsigned)proto);
        return;
    }

    for (li=list; li; li=li->next)
    {
        if ((li->module->validate == fcn) && (li->module->userData == userData))
        {
            clientCreatePattern(proto, pattern, size, position, nocase, li->module);
            break;
        }
    }
}

int load_client_application_plugin(void* symbol)
{
    static THREAD_LOCAL unsigned client_module_index = 0;
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
        list = &client_app_config->tcp_client_app_list;
    else if (cam->proto == IpProtocol::UDP)
        list = &client_app_config->udp_client_app_list;
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
        if (cam->init && cam->init(&client_init_api, nullptr))
            ErrorMessage("Error initializing client %s\n", cam->name);

        client_module_index++;
    }
    /*Can't set cam->userData to nullptr because Lua detectors use it although C detectors don't
      cam->userData = nullptr; */
    return 0;
}


static void AddModuleConfigItem(char* module_name, char* item_name, char* item_value)
{
    SF_LNODE* cursor;
    RNAClientAppModuleConfig* mod_config;
    RNAClientAppModuleConfigItem* item;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&client_app_config->module_configs, &cursor);
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
        sflist_add_tail(&client_app_config->module_configs, mod_config);
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
        sflist_add_tail(&mod_config->items, item);
    }

    if (item->value)
        snort_free((void*)item->value);

    item->value = snort_strdup(item_value);
}

static void ClientAppParseOption(char* key, char* value)
{
    char* p;

    if (!strcasecmp(key, "enable"))
    {
        client_app_config->enabled = atoi(value) ? true : false;
    }
    else if ((p = strchr(key, ':')) && p[1])
    {
        *p = 0;
        AddModuleConfigItem(key, &p[1], value);
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

static int ClientAppParseArgs(SF_LIST* args)
{
    AppidConfigElement* ci;
    SF_LNODE* cursor;

    for (ci = (AppidConfigElement*)sflist_first(args, &cursor);
        ci;
        ci = (AppidConfigElement*)sflist_next(&cursor))
    {
        ClientAppParseOption(ci->name, (char*)ci->value);
    }

#ifdef DEBUG
    DisplayClientAppConfig(client_app_config);
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

static void initialize_module(RNAClientAppRecord* li)
{
    RNAClientAppModuleConfig* mod_config;
    SF_LNODE* cursor;
    int rval;

    for (mod_config = (RNAClientAppModuleConfig*)sflist_first(&client_app_config->module_configs,
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

static int load_builtin_client_plugins()
{
    unsigned i;

    for (i = 0; i < NUM_BUILTIN_CLIENT_PLUGINS; i++)
    {
        if (load_client_application_plugin(builtin_client_plugins[i]))
            return -1;
    }

    return 0;
}

/**
 * Initialize the configuration of the client app module
 *
 * @param args
 */
void init_client_plugins()
{
    RNAClientAppRecord* li;

    client_app_config = new ClientAppConfig;
    if (load_builtin_client_plugins())
         exit(-1);

    sflist_init(&client_app_config->module_configs);
    client_app_config->enabled = true;
    ClientAppParseArgs(&AppIdConfig::get_appid_config()->client_app_args);

    if (client_app_config->enabled)
    {
        client_init_api.debug = AppIdConfig::get_appid_config()->mod_config->debug;
        client_init_api.pAppidConfig = AppIdConfig::get_appid_config();
        client_init_api.instance_id = AppIdConfig::get_appid_config()->mod_config->instance_id;

        for (li = client_app_config->tcp_client_app_list; li; li = li->next)
            initialize_module(li);
        for (li = client_app_config->udp_client_app_list; li; li = li->next)
            initialize_module(li);
        for (li = client_app_config->tcp_client_app_list; li; li = li->next)
            finalize_module(li);
        for (li = client_app_config->udp_client_app_list; li; li = li->next)
            finalize_module(li);
    }
}

void finalize_client_plugins()
{
    if (client_app_config->enabled)
    {
        if ( client_app_config->tcp_patterns )
            client_app_config->tcp_patterns->prep();

        if ( client_app_config->udp_patterns )
            client_app_config->udp_patterns->prep();
    }
}

/**
 * Clean up the configuration of the client app module
 */
void clean_client_plugins()
{
    ClientPatternData* pd;
    RNAClientAppRecord* li;

    if (client_app_config->tcp_patterns)
    {
        delete client_app_config->tcp_patterns;
        client_app_config->tcp_patterns = nullptr;
    }
    if (client_app_config->udp_patterns)
    {
        delete client_app_config->udp_patterns;
        client_app_config->udp_patterns = nullptr;
    }
    while ((pd = client_app_config->pattern_data_list) != nullptr)
    {
        client_app_config->pattern_data_list = pd->next;
        snort_free(pd);
    }

    while ((li=client_app_config->tcp_client_app_list) != nullptr)
    {
        client_app_config->tcp_client_app_list = li->next;
        if (li->module->clean)
            li->module->clean();
        snort_free(li);
    }
    while ((li=client_app_config->udp_client_app_list) != nullptr)
    {
        client_app_config->udp_client_app_list = li->next;
        if (li->module->clean)
            li->module->clean();
        snort_free(li);
    }

    sflist_static_free_all(&client_app_config->module_configs, &free_module_config);

    ClientAppMatch* match;
    while ((match = match_free_list) != nullptr)
    {
        match_free_list = match->next;
        snort_free(match);
    }

    clean_client_port_patterns();
    delete client_app_config;
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

void AppIdAddClientApp(AppIdSession* asd, AppId service_id, AppId id, const char* version)
{
    if (version)
    {
        if (asd->client_version)
        {
            if (strcmp(version, asd->client_version))
            {
                snort_free(asd->client_version);
                asd->client_version = snort_strdup(version);
            }
        }
        else
            asd->client_version = snort_strdup(version);
    }

    asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED);
    asd->client_service_app_id = service_id;
    asd->client_app_id = id;
}

static void AppIdAddClientAppInfo(AppIdSession* asd, const char* info)
{
    if (asd->hsession && !asd->hsession->url)
        asd->hsession->url = snort_strdup(info);
}

static ClientAppMatch* BuildClientPatternList(const Packet* pkt, IpProtocol protocol)
{
    ClientAppMatch* match_list = nullptr;
    SearchTool* patterns;

    if (protocol == IpProtocol::TCP)
        patterns = client_app_config->tcp_patterns;
    else
        patterns = client_app_config->udp_patterns;

    if (!patterns)
        return nullptr;

    patterns->find_all((char*)pkt->data, pkt->dsize, &pattern_match, false, (void*)&match_list);

    return match_list;
}

static const RNAClientAppModule* GetNextFromClientPatternList(ClientAppMatch** match_list)
{
    ClientAppMatch* prev = nullptr;
    ClientAppMatch* max_curr = nullptr;
    ClientAppMatch* max_prev = nullptr;
    unsigned max_count;
    unsigned max_precedence;

    ClientAppMatch* curr = *match_list;
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
static void ClientAppID(Packet* p, const int /*direction*/, AppIdSession* asd)
{
    const RNAClientAppModule* client = nullptr;
    ClientAppMatch* match_list;

#ifdef CLIENT_APP_DEBUG
    _dpd.logMsg("Client");
#endif

    if (!p->dsize)
        return;

    if (asd->rna_client_data != nullptr)
        return;

    if (asd->candidate_client_list != nullptr)
    {
        if (asd->num_candidate_clients_tried > 0)
            return;
    }
    else
    {
        asd->candidate_client_list = (SF_LIST*) snort_calloc(sizeof(SF_LIST));
        sflist_init(asd->candidate_client_list);
        asd->num_candidate_clients_tried = 0;
    }

    match_list = BuildClientPatternList(p, asd->protocol);
    while (asd->num_candidate_clients_tried < MAX_CANDIDATE_CLIENTS)
    {
        const RNAClientAppModule* tmp = GetNextFromClientPatternList(&match_list);
        if (tmp != nullptr)
        {
            SF_LNODE* cursor;

            client = (RNAClientAppModule*)sflist_first(asd->candidate_client_list, &cursor);
            while (client && (client != tmp))
                client = (RNAClientAppModule*)sflist_next(&cursor);
            if (client == nullptr)
            {
                sflist_add_tail(asd->candidate_client_list, (void*)tmp);
                asd->num_candidate_clients_tried++;
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
}

int AppIdDiscoverClientApp(Packet* p, int direction, AppIdSession* rnaData)
{
    if (!client_app_config->enabled)
        return APPID_SESSION_SUCCESS;

    if (direction == APP_ID_FROM_INITIATOR)
    {
        /* get out if we've already tried to validate a client app */
        if (!rnaData->get_session_flags(APPID_SESSION_CLIENT_DETECTED))
            ClientAppID(p, direction, rnaData);
    }
    else if ( rnaData->rnaServiceState != RNA_STATE_STATEFUL
              && rnaData->get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))
        ClientAppID(p, direction, rnaData);

    return APPID_SESSION_SUCCESS;
}

static void* client_app_flowdata_get(AppIdSession* asd, unsigned client_id)
{
    return asd->get_flow_data(client_id);
}

static int client_app_flowdata_add(AppIdSession* asd, void* data, unsigned client_id, AppIdFreeFCN
    fcn)
{
    return asd->add_flow_data(data, client_id, fcn);
}

