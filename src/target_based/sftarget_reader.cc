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
    // FIXIT-M 16k per host is no longer true
    // FIXIT-M init before snort_conf; move to filename and load separately
    // this is a hack to get it going
    uint32_t max = snort_conf ? ScMaxAttrHosts() : DEFAULT_MAX_ATTRIBUTE_HOSTS;
    lookupTable = sfrt_new(DIR_8x16, IPv6, max + 1, (max>>6) + 1);
}

tTargetBasedConfig::~tTargetBasedConfig()
{
    sfrt_cleanup(lookupTable, SFAT_CleanupCallback);
    sfrt_free(lookupTable);
}

static THREAD_LOCAL tTargetBasedConfig* curr_cfg = NULL;
static tTargetBasedConfig* next_cfg = NULL;

// FIXIT-H ensure these are not used by packet threads
static HostAttributeEntry *current_host = NULL;
static ApplicationEntry *current_app = NULL;

ServiceClient sfat_client_or_service;

static char sfat_error_message[SFAT_BUFSZ];
static char sfat_grammar_error_printed=0;
static char sfat_insufficient_space_logged=0;
static char sfat_fatal_error=1;

/*****TODO: cleanup to use config directive *******/
uint32_t SFAT_NumberOfHosts(void)
{
    if ( curr_cfg && curr_cfg->lookupTable )
    {
        return sfrt_num_entries(curr_cfg->lookupTable);
    }

    return 0;
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

int SFAT_AddService(HostAttributeEntry* host, ApplicationEntry* app)
{
    current_host = host;
    current_app = app;
    AppendApplicationData(&host->services);
    return SFAT_OK;
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
            host->hostInfo.streamPolicyName, host->hostInfo.streamPolicySet ? "set":"unset", host->hostInfo.streamPolicy);
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

int SFAT_AddHost(HostAttributeEntry* host)
{
    current_host = host;
    return SFAT_AddHostEntryToMap();
}

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

HostAttributeEntry *SFAT_LookupHostEntryByIP(const sfip_t *ipAddr)
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
    if (!p || !p->ip_api.is_valid())
        return NULL;

    return SFAT_LookupHostEntryByIP(p->ip_api.get_src());
}

HostAttributeEntry *SFAT_LookupHostEntryByDst(Packet *p)
{
    if (!p || !p->ip_api.is_valid())
        return NULL;

    return SFAT_LookupHostEntryByIP(p->ip_api.get_dst());
}

void SFAT_Cleanup(void)
{
    delete curr_cfg;
    delete next_cfg;

    FreeProtoocolReferenceTable();
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

void SFAT_Init()
{
    curr_cfg = nullptr;
    next_cfg = new tTargetBasedConfig;
    InitializeProtocolReferenceTable();
}

void SFAT_Start()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;
}

tTargetBasedConfig* SFAT_Swap()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;

    sfBase.iAttributeHosts = SFAT_NumberOfHosts();
    sfBase.iAttributeReloads++;
    proc_stats.attribute_table_reloads++;

    LogMessage("Attribute Table Loaded with " STDu64 " hosts\n", sfBase.iAttributeHosts);
    return curr_cfg;
}

int IsAdaptiveConfigured()
{
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

