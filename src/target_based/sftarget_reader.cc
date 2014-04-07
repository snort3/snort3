/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2006-2013 Sourcefire, Inc.
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

/*
 * Author: Steven Sturges
 * sftarget_reader.c
 */

#include "sftarget_reader.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "mstring.h"
#include "util.h"
#include "parser.h"
#include "sftarget_protocol_reference.h"
#include "sfrt/sfrt.h"
#include "hash/sfxhash.h"
#include "utils/util_net.h"
#include "sftarget_hostentry.h"
#include "sftarget_data.h"
#include "perf_monitor/perf.h"
#include "snort.h"
#include "snort_debug.h"

#define SFAT_CHECKHOST \
    if (!current_host) return SFAT_ERROR;
#define SFAT_CHECKAPP \
    if (!current_app) return SFAT_ERROR;

#define ATTRIBUTE_MAP_MAX_ROWS 1024

struct tTargetBasedConfig
{
    table_t* lookupTable;
    SFXHASH* mapTable;

    tTargetBasedConfig();
    ~tTargetBasedConfig();
};

void SFAT_CleanupCallback(void *host_attr_ent)
{
    HostAttributeEntry *host_entry = (HostAttributeEntry*)host_attr_ent;
    FreeHostEntry(host_entry);
}

tTargetBasedConfig::tTargetBasedConfig()
{
    /* Add 1 to max for table purposes
    * We use max_hosts to limit memcap, assume 16k per entry costs*/
    // FIXIT 16k per host is no longer true
    lookupTable = sfrt_new(
        DIR_8x16, IPv6, ScMaxAttrHosts() + 1,
        ((ScMaxAttrHosts())>>6) + 1);

    /* Attribute Table node includes memory for each entry,
     * as defined by sizeof(MapEntry).
     */
    mapTable = sfxhash_new(
        ATTRIBUTE_MAP_MAX_ROWS,
        sizeof(int), sizeof(MapEntry),
        0, 1, NULL, NULL, 1);
}

tTargetBasedConfig::~tTargetBasedConfig()
{
    sfxhash_delete(mapTable);
    sfrt_cleanup(lookupTable, SFAT_CleanupCallback);
    sfrt_free(lookupTable);
}

static THREAD_LOCAL tTargetBasedConfig* curr_cfg = NULL;
static tTargetBasedConfig* next_cfg = NULL;

// FIXIT ensure these are not used by packet threads
static HostAttributeEntry *current_host = NULL;
static ApplicationEntry *current_app = NULL;

ServiceClient sfat_client_or_service;

extern char sfat_error_message[SFAT_BUFSZ];
extern char sfat_grammar_error_printed;
extern char sfat_insufficient_space_logged;
extern char sfat_fatal_error;

extern "C" {
int ParseTargetMap(char *filename);
void DestroyBufferStack(void);
}

extern char *sfat_saved_file;

/*****TODO: cleanup to use config directive *******/
uint32_t SFAT_NumberOfHosts(void)
{
    if ( curr_cfg && curr_cfg->lookupTable )
    {
        return sfrt_num_entries(curr_cfg->lookupTable);
    }

    return 0;
}

int SFAT_AddMapEntry(MapEntry *entry)
{
    /* Memcopy MapEntry to newly allocated one and store in
     * a hash table based on entry->id for easy lookup.
     */

    DEBUG_WRAP(
        DebugMessage(DEBUG_ATTRIBUTE, "Adding Map Entry: %d %s\n",
            entry->l_mapid, entry->s_mapvalue););

    /* Data from entry will be copied into new node */
    sfxhash_add(next_cfg->mapTable, &entry->l_mapid, entry);

    return SFAT_OK;
}

char *SFAT_LookupAttributeNameById(int id)
{
    MapEntry *entry;

    if (!next_cfg->mapTable)
        return NULL;

    entry = (MapEntry*)sfxhash_find(next_cfg->mapTable, &id);

    if (entry)
    {
        DEBUG_WRAP(
            DebugMessage(DEBUG_ATTRIBUTE, "Found Attribute Name %s for Id %d\n",
                entry->s_mapvalue, id););
        return entry->s_mapvalue;
    }
    DEBUG_WRAP(
        DebugMessage(DEBUG_ATTRIBUTE, "No Attribute Name for Id %d\n", id););

    return NULL;
}

void FreeApplicationEntry(ApplicationEntry *app)
{
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Freeing ApplicationEntry: 0x%x\n",
        app););
    free(app);
}

ApplicationEntry * SFAT_CreateApplicationEntry(void)
{
    if (current_app)
    {
        /* Something went wrong */
        FreeApplicationEntry(current_app);
        current_app = NULL;
    }

    current_app = (ApplicationEntry*)SnortAlloc(sizeof(ApplicationEntry));

    return current_app;
}

HostAttributeEntry* SFAT_CreateHostEntry(void)
{
    if (current_host)
    {
        /* Something went wrong */
        FreeHostEntry(current_host);
        current_host = NULL;
    }

    current_host = (HostAttributeEntry*)SnortAlloc(sizeof(HostAttributeEntry));

    return current_host;
}

void FreeHostEntry(HostAttributeEntry *host)
{
    ApplicationEntry *app = NULL, *tmp_app;

    if (!host)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Freeing HostEntry: 0x%x\n",
        host););

    /* Free the service list */
    if (host->services)
    {
        do
        {
            tmp_app = host->services;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->services = app;
        } while (app);
    }

    /* Free the client list */
    if (host->clients)
    {
        do
        {
            tmp_app = host->clients;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->clients = app;
        } while (app);
    }

    free(host);
}

void PrintAttributeData(char *prefix, AttributeData *data)
{
#ifdef DEBUG_MSGS
    DebugMessage(DEBUG_ATTRIBUTE, "AttributeData for %s\n", prefix);
    if (data->type == ATTRIBUTE_NAME)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\ttype: %s\tname: %s\t confidence %d\n",
                "Name", data->value.s_value, data->confidence);
    }
    else
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\ttype: %s\tid: %s\t confidence %d",
                "Id", data->value.l_value, data->confidence);
    }
#else
    UNUSED(prefix);
    UNUSED(data);
#endif
}

int SFAT_SetHostIp(char *ip)
{
    static THREAD_LOCAL HostAttributeEntry *tmp_host = NULL;
    sfip_t ipAddr;
    SFAT_CHECKHOST;

    if (sfip_pton(ip, &ipAddr) != SFIP_SUCCESS)
    {
        return SFAT_ERROR;
    }

    if (ipAddr.family == AF_INET)
    {
        ipAddr.ip32[0] = ntohl(ipAddr.ip32[0]);
    }

    tmp_host = (HostAttributeEntry*)sfrt_lookup(&ipAddr, next_cfg->lookupTable);

    if (tmp_host &&
        sfip_equals(tmp_host->ipAddr, ipAddr))
    {
        /* Exact match. */
        FreeHostEntry(current_host);
        current_host = tmp_host;
    }
    else
    {
        /* New entry for this host/CIDR */
        sfip_set_ip(&current_host->ipAddr, &ipAddr);
    }
    return SFAT_OK;
}

int SFAT_SetOSPolicy(char *policy_name, int attribute)
{
    SFAT_CHECKHOST;

    switch (attribute)
    {
        case HOST_INFO_FRAG_POLICY:
            SnortStrncpy(current_host->hostInfo.fragPolicyName, policy_name,
                sizeof(current_host->hostInfo.fragPolicyName));
            break;
        case HOST_INFO_STREAM_POLICY:
            SnortStrncpy(current_host->hostInfo.streamPolicyName, policy_name,
                sizeof(current_host->hostInfo.streamPolicyName));
            break;
    }
    return SFAT_OK;
}

int SFAT_SetOSAttribute(AttributeData*, int)
{
    SFAT_CHECKHOST;
    // currently not using os, vendor, or version
    return SFAT_OK;
}

static void AppendApplicationData(ApplicationList **list)
{
    if (!list)
        return;

    if (*list)
    {
        current_app->next = *list;
    }
    *list = current_app;
    current_app = NULL;
}


int SFAT_AddApplicationData(void)
{
    uint8_t required_fields;
    SFAT_CHECKAPP;
    SFAT_CHECKHOST;

    if (sfat_client_or_service == ATTRIBUTE_SERVICE)
    {
        required_fields = (APPLICATION_ENTRY_PORT |
                          APPLICATION_ENTRY_IPPROTO |
                          APPLICATION_ENTRY_PROTO);
        if ((current_app->fields & required_fields) != required_fields)
        {
            sfip_t host_addr;
            sfip_set_ip(&host_addr, &current_host->ipAddr);
            host_addr.ip32[0] = ntohl(host_addr.ip32[0]);
            ParseError("Missing required field in Service attribute table for host %s",
                inet_ntoa(&host_addr));
        }

        AppendApplicationData(&current_host->services);
    }
    else
    {
        required_fields = (APPLICATION_ENTRY_PROTO);
        /* Currently, client data only includes PROTO, not IPPROTO */
        if ((current_app->fields & required_fields) != required_fields)
        {
            sfip_t host_addr;
            sfip_set_ip(&host_addr, &current_host->ipAddr);
            host_addr.ip32[0] = ntohl(host_addr.ip32[0]);
            ParseError("Missing required field in Client attribute table for host %s",
                inet_ntoa(&host_addr));
        }

        AppendApplicationData(&current_host->clients);
    }
    return SFAT_OK;
}

int SFAT_SetApplicationAttribute(AttributeData *data, int attribute)
{
    SFAT_CHECKAPP;

    switch(attribute)
    {
        case APPLICATION_ENTRY_PORT:
            /* Convert the port to a integer */
            if (data->type == ATTRIBUTE_NAME)
            {
                char *endPtr = NULL;
                unsigned long value = SnortStrtoul(data->value.s_value, &endPtr, 10);
                if ((endPtr == &data->value.s_value[0]) ||
                    (errno == ERANGE) || value > UINT16_MAX)
                {
                    current_app->port = 0;
                    return SFAT_ERROR;
                }

                current_app->port = (uint16_t)value;
            }
            else
            {
                if (data->value.l_value > UINT16_MAX)
                {
                    current_app->port = 0;
                    return SFAT_ERROR;
                }

                current_app->port = (uint16_t)data->value.l_value;
            }
            break;
        case APPLICATION_ENTRY_IPPROTO:
            /* Add IP Protocol to the reference list */
            current_app->ipproto = AddProtocolReference(data->value.s_value);
            break;
        case APPLICATION_ENTRY_PROTO:
            /* Add Application Protocol to the reference list */
            current_app->protocol = AddProtocolReference(data->value.s_value);
            break;
        // currently not using application or version
        default:
            attribute = 0;
    }
    current_app->fields |= attribute;

    return SFAT_OK;
}

#ifdef DEBUG_MSGS
void PrintHostAttributeEntry(HostAttributeEntry *host)
{
    ApplicationEntry *app;
    int i = 0;
    sfip_t host_addr;

    if (!host)
        return;

    sfip_set_ip(&host_addr, &host->ipAddr);
    host_addr.ip32[0] = ntohl(host_addr.ip32[0]);

    DebugMessage(DEBUG_ATTRIBUTE, "Host IP: %s/%d\n",
            inet_ntoa(&host_addr),
            host->ipAddr.bits
            );
    DebugMessage(DEBUG_ATTRIBUTE, "\tPolicy Information: frag:%s (%s %u) stream: %s (%s %u)\n",
            host->hostInfo.fragPolicyName, host->hostInfo.fragPolicySet ? "set":"unset", host->hostInfo.fragPolicy,
            host->hostInfo.fragPolicyName, host->hostInfo.streamPolicySet ? "set":"unset", host->hostInfo.streamPolicy);
    DebugMessage(DEBUG_ATTRIBUTE, "\tServices:\n");
    for (i=0, app = host->services; app; app = app->next,i++)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tService #%d:\n", i);
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s\tPort: %s\tProtocol %s\n",
                app->ipproto, app->port, app->protocol);
    }
    if (i==0)
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");

    DebugMessage(DEBUG_ATTRIBUTE, "\tClients:\n");
    for (i=0, app = host->clients; app; app = app->next,i++)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tClient #%d:\n", i);
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s\tProtocol %s\n",
                app->ipproto, app->protocol);

        if (app->fields & APPLICATION_ENTRY_PORT)
        {
            DebugMessage(DEBUG_ATTRIBUTE, "\t\tPort: %s\n", app->port);
        }
    }
    if (i==0)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");
    }
}
#endif

int SFAT_AddHostEntryToMap(void)
{
    HostAttributeEntry *host = current_host;
    int ret;
    sfip_t *ipAddr;

    SFAT_CHECKHOST;

    DEBUG_WRAP(PrintHostAttributeEntry(host););

    ipAddr = &host->ipAddr;

    ret = sfrt_insert(ipAddr, (unsigned char)ipAddr->bits, host,
                        RT_FAVOR_SPECIFIC, next_cfg->lookupTable);

    if (ret != RT_SUCCESS)
    {
        if (ret == RT_POLICY_TABLE_EXCEEDED)
        {
            if (!sfat_insufficient_space_logged)
            {
                SnortSnprintf(sfat_error_message, SFAT_BUFSZ,
                    "AttributeTable insertion failed: %d Insufficient "
                    "space in attribute table, only configured to store %d hosts\n",
                    ret, ScMaxAttrHosts());
                sfat_grammar_error_printed = 1;
                sfat_insufficient_space_logged = 1;
                sfat_fatal_error = 0;
            }
            /* Reset return value and continue w/ only snort_conf->max_attribute_hosts */
            ret = RT_SUCCESS;
        }
        else
        {
            SnortSnprintf(sfat_error_message, SFAT_BUFSZ,
                "AttributeTable insertion failed: %d '%s'\n",
                ret, rt_error_messages[ret]);
            sfat_grammar_error_printed = 1;
        }

        FreeHostEntry(host);
    }

    current_host = NULL;

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

HostAttributeEntry *SFAT_LookupHostEntryByIP(sfip_t *ipAddr)
{
    HostAttributeEntry *host = NULL;
    sfip_t local_ipAddr;

    if ( !curr_cfg )
        return NULL;

    sfip_set_ip(&local_ipAddr, ipAddr);
    if (local_ipAddr.family == AF_INET)
    {
        local_ipAddr.ip32[0] = ntohl(local_ipAddr.ip32[0]);
    }

    host = (HostAttributeEntry*)sfrt_lookup(&local_ipAddr, curr_cfg->lookupTable);

    if (host)
    {
        /* Set the policy values for Frag & Stream if not already set */
        //TODO: SetTargetBasedPolicy(host);
    }

    return host;
}

HostAttributeEntry *SFAT_LookupHostEntryBySrc(Packet *p)
{
    if (!p || !p->iph_api)
        return NULL;

    return SFAT_LookupHostEntryByIP(GET_SRC_IP(p));
}

HostAttributeEntry *SFAT_LookupHostEntryByDst(Packet *p)
{
    if (!p || !p->iph_api)
        return NULL;

    return SFAT_LookupHostEntryByIP(GET_DST_IP(p));
}

// FIXIT this looks like a problem with multiple packet threads
static THREAD_LOCAL GetPolicyIdFunc updatePolicyCallback;
static THREAD_LOCAL GetPolicyIdsCallbackList *updatePolicyCallbackList = NULL;

void SFAT_SetPolicyCallback(void *host_attr_ent)
{
    HostAttributeEntry *host_entry = (HostAttributeEntry*)host_attr_ent;

    if (!host_entry)
        return;

    updatePolicyCallback(host_entry);

    return;
}

void SFAT_SetPolicyIds(GetPolicyIdFunc policyCallback)
{
    if ( !curr_cfg )
        return;

    GetPolicyIdsCallbackList *list_entry, *new_list_entry = NULL;

    updatePolicyCallback = policyCallback;

    sfrt_iterate(curr_cfg->lookupTable, SFAT_SetPolicyCallback);

    if (!updatePolicyCallbackList)
    {
        /* No list present, so no attribute table... bye-bye */
        return;
    }

    /* Look for this callback in the list */
    list_entry = updatePolicyCallbackList;
    while (list_entry)
    {
        if (list_entry->policyCallback == policyCallback)
            return; /* We're done with this one */

        if (list_entry->next)
        {
            list_entry = list_entry->next;
        }
        else
        {
            /* Leave list_entry pointing to last node in list */
            break;
        }
    }

    /* Wasn't there, add it so that when we reload the table,
     * we can set those policy entries on reload. */
    new_list_entry = (GetPolicyIdsCallbackList *)SnortAlloc(sizeof(GetPolicyIdsCallbackList));
    new_list_entry->policyCallback = policyCallback;
    if (list_entry)
    {
        /* list_entry is valid here since there was at least an
         * empty head entry in the list. */
        list_entry->next = new_list_entry;
    }
}

void SFAT_Cleanup(void)
{
    GetPolicyIdsCallbackList *list_entry, *tmp_list_entry = NULL;

    delete curr_cfg;
    delete next_cfg;

    FreeProtoocolReferenceTable();

    if (sfat_saved_file)
    {
        free(sfat_saved_file);
        sfat_saved_file = NULL;
    }

    if (updatePolicyCallbackList)
    {
        list_entry = updatePolicyCallbackList;
        while (list_entry)
        {
            tmp_list_entry = list_entry->next;
            free(list_entry);
            list_entry = tmp_list_entry;
        }
        updatePolicyCallbackList = NULL;
    }

    DestroyBufferStack();
}

tTargetBasedConfig* SFAT_Reload()
{
    if ( !sfat_saved_file )
        return nullptr;

    // create new table
    if ( ParseTargetMap(sfat_saved_file) == SFAT_OK )
    {
        GetPolicyIdsCallbackList *list_entry = NULL;

        /* Set the policy IDs in the new table... */
        list_entry = updatePolicyCallbackList;

        while (list_entry)
        {
            if (list_entry->policyCallback)
            {
                sfrt_iterate(next_cfg->lookupTable,
                    (sfrt_iterator_callback)list_entry->policyCallback);
            }
            list_entry = list_entry->next;
        }
    }
    else
    {
        /* Failed to parse, clean it up */
        delete next_cfg;
        next_cfg = new tTargetBasedConfig; // FIXIT should not need this
        return nullptr;
    }
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;

    sfBase.iAttributeHosts = SFAT_NumberOfHosts();
    sfBase.iAttributeReloads++;
    proc_stats.attribute_table_reloads++;

    LogMessage("Attribute Table Loaded with " STDu64 " hosts\n", sfBase.iAttributeHosts);
    return curr_cfg;
}

void SFAT_SetConfig(tTargetBasedConfig* p)
{
    curr_cfg = p;
}

tTargetBasedConfig* SFAT_GetConfig()
{
    return curr_cfg;
}

void SFAT_Free(tTargetBasedConfig* p)
{
    delete p;
}

/**called once during initialization. Reads attribute table for the first time.*/
int SFAT_ParseAttributeTable(const char *args)
{
    char **toks;
    int num_toks;
    int ret;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"AttributeTable\n"););

    // FIXIT should only need one of these
    curr_cfg = new tTargetBasedConfig;
    next_cfg = new tTargetBasedConfig;

    /* Parse filename */
    toks = mSplit(args, " \t", 0, &num_toks, 0);

    if (num_toks != 2)
    {
        ParseError("attribute_table must have 2 parameters");
    }

    if (!(strcasecmp(toks[0], "filename") == 0))
    {
        ParseError("attribute_table must have 2 arguments, the 1st "
                "is 'filename'");
    }

    /* Reset... */
    sfat_insufficient_space_logged = 0;
    sfat_fatal_error = 1;

    ret = ParseTargetMap(toks[1]);

    if (ret == SFAT_OK)
    {
        tTargetBasedConfig* tmp = curr_cfg;
        curr_cfg = next_cfg;
        next_cfg = tmp;

        if (sfat_insufficient_space_logged)
            LogMessage("%s", sfat_error_message);
    }
    else
    {
        LogMessage("%s", sfat_error_message);
        if (sfat_fatal_error)
            ParseError("failed to load attribute table from %s", toks[1]);
    }
    mSplitFree(&toks, num_toks);

    sfBase.iAttributeHosts = SFAT_NumberOfHosts();
    LogMessage("Attribute Table Loaded with " STDu64 " hosts\n", sfBase.iAttributeHosts);

    updatePolicyCallbackList =
        (GetPolicyIdsCallbackList *)SnortAlloc(sizeof(GetPolicyIdsCallbackList));

    return SFAT_OK;
}

int IsAdaptiveConfigured()
{
    if ( !curr_cfg )
        return 0;

    return 1;
}

int IsAdaptiveConfiguredForSnortConfig(SnortConfig* sc)
{
    if ( !sc->attribute_file )
        return 0;

    if ( !curr_cfg )
        return 0;

    return 1;
}

void SFAT_UpdateApplicationProtocol(sfip_t *ipAddr, uint16_t port, uint16_t protocol, uint16_t id)
{
    HostAttributeEntry *host_entry;
    ApplicationEntry *service;
    sfip_t local_ipAddr;
    unsigned service_count = 0;
    int rval;

    sfip_set_ip(&local_ipAddr, ipAddr);
    if (local_ipAddr.family == AF_INET)
        local_ipAddr.ip32[0] = ntohl(local_ipAddr.ip32[0]);

    host_entry = (HostAttributeEntry*)sfrt_lookup(&local_ipAddr, curr_cfg->lookupTable);

    if (!host_entry)
    {
        GetPolicyIdsCallbackList *list_entry;

        if (sfrt_num_entries(curr_cfg->lookupTable) >= ScMaxAttrHosts())
            return;

        host_entry = (HostAttributeEntry*)SnortAlloc(sizeof(*host_entry));
        sfip_set_ip(&host_entry->ipAddr, &local_ipAddr);
        if ((rval = sfrt_insert(&local_ipAddr, (unsigned char)local_ipAddr.bits, host_entry,
                                RT_FAVOR_SPECIFIC, curr_cfg->lookupTable)) != RT_SUCCESS)
        {
            FreeHostEntry(host_entry);
            return;
        }
        for (list_entry = updatePolicyCallbackList; list_entry; list_entry = list_entry->next)
        {
            if (list_entry->policyCallback)
                list_entry->policyCallback(host_entry);
        }
        service = NULL;
    }
    else
    {
        for (service = host_entry->services; service; service = service->next)
        {
            if (service->ipproto == protocol && (uint16_t)service->port == port)
            {
                break;
            }
            service_count++;
        }
    }
    if (!service)
    {
        if ( service_count >= ScMaxAttrServicesPerHost() )
            return;

        service = (ApplicationEntry*)SnortAlloc(sizeof(*service));
        service->port = port;
        service->ipproto = protocol;
        service->next = host_entry->services;
        host_entry->services = service;
        service->protocol = id;
    }
    else if (service->protocol != id)
    {
        service->protocol = id;
    }
}

