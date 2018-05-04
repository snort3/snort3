//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

/*
 * Author: Steven Sturges
 * sftarget_reader.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sftarget_reader.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "sfrt/sfrt.h"
#include "utils/stats.h"
#include "utils/util.h"

using namespace snort;

#define ATTRIBUTE_MAP_MAX_ROWS 1024

struct tTargetBasedConfig
{
    table_t* lookupTable;

    tTargetBasedConfig();
    ~tTargetBasedConfig();
};

static void SFAT_CleanupCallback(void* host_attr_ent)
{
    HostAttributeEntry* host_entry = (HostAttributeEntry*)host_attr_ent;
    FreeHostEntry(host_entry);
}

tTargetBasedConfig::tTargetBasedConfig()
{
    /* Add 1 to max for table purposes
    * We use max_hosts to limit memcap, assume 16k per entry costs*/
    // FIXIT-M 16k per host is no longer true
    // FIXIT-M init before snort_conf; move to filename and load separately
    // this is a hack to get it going
    uint32_t max = SnortConfig::get_conf() ?
        SnortConfig::get_max_attribute_hosts() : DEFAULT_MAX_ATTRIBUTE_HOSTS;
    lookupTable = sfrt_new(DIR_8x16, IPv6, max + 1, (max>>6) + 1);
}

tTargetBasedConfig::~tTargetBasedConfig()
{
    sfrt_cleanup(lookupTable, SFAT_CleanupCallback);
    sfrt_free(lookupTable);
}

static THREAD_LOCAL tTargetBasedConfig* curr_cfg = nullptr;
static tTargetBasedConfig* next_cfg = nullptr;

static bool sfat_grammar_error_printed = false;
static bool sfat_insufficient_space_logged = false;

/*****TODO: cleanup to use config directive *******/
uint32_t SFAT_NumberOfHosts()
{
    if ( curr_cfg && curr_cfg->lookupTable )
    {
        return sfrt_num_entries(curr_cfg->lookupTable);
    }

    return 0;
}

static void FreeApplicationEntry(ApplicationEntry* app)
{
    snort_free(app);
}

ApplicationEntry* SFAT_CreateApplicationEntry()
{
    return (ApplicationEntry*)snort_calloc(sizeof(ApplicationEntry));
}

HostAttributeEntry* SFAT_CreateHostEntry()
{
    return (HostAttributeEntry*)snort_calloc(sizeof(HostAttributeEntry));
}

void FreeHostEntry(HostAttributeEntry* host)
{
    ApplicationEntry* app = nullptr, * tmp_app;

    if (!host)
        return;


    /* Free the service list */
    if (host->services)
    {
        do
        {
            tmp_app = host->services;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->services = app;
        }
        while (app);
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
        }
        while (app);
    }

    snort_free(host);
}

static void AppendApplicationData(ApplicationEntry** list, ApplicationEntry* app)
{
    if (!list)
        return;

    if (*list)
    {
        app->next = *list;
    }
    *list = app;
}

int SFAT_AddService(HostAttributeEntry* host, ApplicationEntry* app)
{
    AppendApplicationData(&host->services, app);
    return SFAT_OK;
}

#if 0
int SFAT_AddApplicationData(HostAttributeEntry* host, ApplicationEntry* app)
{
    uint8_t required_fields =
        (APPLICATION_ENTRY_PORT |
        APPLICATION_ENTRY_IPPROTO |
        APPLICATION_ENTRY_PROTO);

    if ((app->fields & required_fields) != required_fields)
    {
        ParseError("Missing required field in Service attribute table for host %s",
            host->ipAddr.ntoa());
    }
    AppendApplicationData(&host->services, app);

    return SFAT_OK;
}

#endif


int SFAT_AddHost(HostAttributeEntry* host)
{
    return SFAT_AddHostEntryToMap(host);
}

int SFAT_AddHostEntryToMap(HostAttributeEntry* host)
{
    int ret;
    SfCidr* ipAddr;

    ipAddr = &host->ipAddr;
    assert(ipAddr);

    ret = sfrt_insert(ipAddr, (unsigned char)ipAddr->get_bits(), host,
        RT_FAVOR_SPECIFIC, next_cfg->lookupTable);

    if (ret != RT_SUCCESS)
    {
        if (ret == RT_POLICY_TABLE_EXCEEDED)
        {
            if ( !sfat_insufficient_space_logged )
            {
                ParseWarning(WARN_HOSTS,
                    "AttributeTable insertion failed: %d Insufficient "
                    "space in attribute table, only configured to store %u hosts\n",
                    ret, SnortConfig::get_max_attribute_hosts());
                sfat_insufficient_space_logged = true;
            }
            /* Reset return value and continue w/ only SnortConfig::get_conf()->max_attribute_hosts */
            ret = RT_SUCCESS;
        }
        else if ( !sfat_grammar_error_printed )
        {
            ParseWarning(WARN_HOSTS,
                "AttributeTable insertion failed: %d '%s'\n",
                ret, rt_error_messages[ret]);
            sfat_grammar_error_printed = true;
        }

        FreeHostEntry(host);
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

HostAttributeEntry* SFAT_LookupHostEntryByIP(const SfIp* ipAddr)
{
    if ( !curr_cfg )
        return nullptr;

    return (HostAttributeEntry*)sfrt_lookup((const SfIp*)ipAddr, curr_cfg->lookupTable);
}

HostAttributeEntry* SFAT_LookupHostEntryBySrc(Packet* p)
{
    if (!p || !p->ptrs.ip_api.is_ip())
        return nullptr;

    return SFAT_LookupHostEntryByIP(p->ptrs.ip_api.get_src());
}

HostAttributeEntry* SFAT_LookupHostEntryByDst(Packet* p)
{
    if (!p || !p->ptrs.ip_api.is_ip())
        return nullptr;

    return SFAT_LookupHostEntryByIP(p->ptrs.ip_api.get_dst());
}

void SFAT_Cleanup()
{
    delete curr_cfg;
    delete next_cfg;
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
}

void SFAT_Start()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;
    proc_stats.attribute_table_hosts = SFAT_NumberOfHosts();
}

tTargetBasedConfig* SFAT_Swap()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;

    proc_stats.attribute_table_hosts = SFAT_NumberOfHosts();
    proc_stats.attribute_table_reloads++;

    LogMessage(STDu64 " hosts loaded\n", proc_stats.attribute_table_hosts);
    return curr_cfg;
}

void SFAT_UpdateApplicationProtocol(SfIp* ipAddr, uint16_t port, uint16_t protocol, SnortProtocolId snort_protocol_id)
{
    HostAttributeEntry* host_entry;
    ApplicationEntry* service;
    unsigned service_count = 0;

    host_entry = (HostAttributeEntry*)sfrt_lookup(ipAddr, curr_cfg->lookupTable);

    if (!host_entry)
    {
        if (sfrt_num_entries(curr_cfg->lookupTable) >= SnortConfig::get_max_attribute_hosts())
            return;

        host_entry = (HostAttributeEntry*)snort_calloc(sizeof(*host_entry));
        host_entry->ipAddr.set(*ipAddr);

        int rval = sfrt_insert(&host_entry->ipAddr, (unsigned char)host_entry->ipAddr.get_bits(),
            host_entry, RT_FAVOR_SPECIFIC, curr_cfg->lookupTable);

        if ( rval != RT_SUCCESS)
        {
            FreeHostEntry(host_entry);
            return;
        }
        service = nullptr;
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
        if ( service_count >= SnortConfig::get_max_services_per_host() )
            return;

        service = (ApplicationEntry*)snort_calloc(sizeof(*service));
        service->port = port;
        service->ipproto = protocol;
        service->next = host_entry->services;
        host_entry->services = service;
        service->snort_protocol_id = snort_protocol_id;
    }
    else if (service->snort_protocol_id != snort_protocol_id)
    {
        service->snort_protocol_id = snort_protocol_id;
    }
}

