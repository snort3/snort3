//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// service_map.cc based on fpcreate.cc by:
/*
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
**
**  NOTES
**  5.7.02 - Initial Checkin. Norton/Roelker
**
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data
**
*/

#include "service_map.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/snort_config.h"
#include "hash/sfghash.h"
#include "utils/sflsq.h"
#include "ips_options/ips_flow.h"
#include "detection/treenodes.h"
#include "detection/fp_detect.h"
#include "parser/parser.h"

static SFGHASH* alloc_srvmap()
{
    SFGHASH* p = sfghash_new(1000,
        0,
        0,
        /*nodes are lists,free them in sfghash_delete*/
        (void (*)(void*))sflist_free);
    if (p == NULL)
        FatalError("could not allocate a service rule map - no memory?\n");

    return p;
}

srmm_table_t* ServiceMapNew()
{
    srmm_table_t* table = (srmm_table_t*)SnortAlloc(sizeof(srmm_table_t));

    table->ip_to_srv = alloc_srvmap();
    table->ip_to_cli = alloc_srvmap();

    table->icmp_to_srv = alloc_srvmap();
    table->icmp_to_cli = alloc_srvmap();

    table->tcp_to_srv = alloc_srvmap();
    table->tcp_to_cli = alloc_srvmap();

    table->udp_to_srv = alloc_srvmap();
    table->udp_to_cli = alloc_srvmap();

    table->svc_to_srv = alloc_srvmap();
    table->svc_to_cli = alloc_srvmap();

    return table;
}

void ServiceTableFree(SFGHASH* table)
{
    if (table != NULL)
        sfghash_delete(table);
}

void ServiceMapFree(srmm_table_t* srvc_map)
{
    if (srvc_map == NULL)
        return;

    ServiceTableFree(srvc_map->ip_to_srv);
    ServiceTableFree(srvc_map->ip_to_cli);

    ServiceTableFree(srvc_map->icmp_to_srv);
    ServiceTableFree(srvc_map->icmp_to_cli);

    ServiceTableFree(srvc_map->tcp_to_srv);
    ServiceTableFree(srvc_map->tcp_to_cli);

    ServiceTableFree(srvc_map->udp_to_srv);
    ServiceTableFree(srvc_map->udp_to_cli);

    ServiceTableFree(srvc_map->svc_to_srv);
    ServiceTableFree(srvc_map->svc_to_cli);

    free(srvc_map);
}

static SFGHASH* alloc_spgmm()
{
    SFGHASH* p;

    /* TODO: keys are ascii service names - for now ! */
    p = sfghash_new(1000, /* # rows in table */
        0,            /* size: of key 0 = ascii, >0 = fixed size */
        0,            /* bool:user keys,  if true just store this pointer, don't copy the key */
        fpDeletePortGroup);
    /* ??? Why shouldn't we delete the port groups ??? */
    //(void(*)(void*))0 /* free nodes are port_groups do not delete here */ );

    if (p == NULL)
        FatalError("could not allocate a service port_group map : no memory?\n");

    return p;
}

srmm_table_t* ServicePortGroupMapNew()
{
    srmm_table_t* table = (srmm_table_t*)SnortAlloc(sizeof(srmm_table_t));

    table->ip_to_srv = alloc_spgmm();
    table->ip_to_cli = alloc_spgmm();

    table->icmp_to_srv = alloc_spgmm();
    table->icmp_to_cli = alloc_spgmm();

    table->tcp_to_srv = alloc_spgmm();
    table->tcp_to_cli = alloc_spgmm();

    table->udp_to_srv = alloc_spgmm();
    table->udp_to_cli = alloc_spgmm();

    table->svc_to_srv = alloc_spgmm();
    table->svc_to_cli = alloc_spgmm();

    return table;
}

static void ServicePortGroupTableFree(SFGHASH* table)
{
#if 0
    SFGHASH_NODE* node;
    PortGroup* pg;

    /* Not sure why we wouldn't want to free the data */
    for (node = sfghash_findfirst(table);
        node != NULL;
        node = sfghash_findnext(table))
    {
        pg = (PortGroup*)node->data;
        if (pg == NULL)
            continue;

        /* XXX XXX (if we need to recycle these) free the PortGroup */
        node->data = NULL;
    }
#endif

    if (table == NULL)
        return;

    sfghash_delete(table);
}

void ServicePortGroupMapFree(srmm_table_t* srvc_pg_map)
{
    if (srvc_pg_map == NULL)
        return;

    ServicePortGroupTableFree(srvc_pg_map->ip_to_srv);
    ServicePortGroupTableFree(srvc_pg_map->ip_to_cli);

    ServicePortGroupTableFree(srvc_pg_map->icmp_to_srv);
    ServicePortGroupTableFree(srvc_pg_map->icmp_to_cli);

    ServicePortGroupTableFree(srvc_pg_map->tcp_to_srv);
    ServicePortGroupTableFree(srvc_pg_map->tcp_to_cli);

    ServicePortGroupTableFree(srvc_pg_map->udp_to_srv);
    ServicePortGroupTableFree(srvc_pg_map->udp_to_cli);

    ServicePortGroupTableFree(srvc_pg_map->svc_to_srv);
    ServicePortGroupTableFree(srvc_pg_map->svc_to_cli);

    free(srvc_pg_map);
}

/*
 * Add the otn to the list stored by the key = servicename.
 *
 * table - table of service/otn-list pairs
 * servicename - ascii service name from rule metadata option
 * otn - rule - may be content,-no-content, or uri-content
 *
 */
static void ServiceMapAddOtnRaw(SFGHASH* table, char* servicename, OptTreeNode* otn)
{
    SF_LIST* list;

    list = (SF_LIST*)sfghash_find(table, servicename);

    if ( !list )
    {
        /* create the list */
        list = sflist_new();
        if ( !list )
            FatalError("service_rule_map: could not create a  service rule-list\n");

        /* add the service list to the table */
        if ( sfghash_add(table, servicename, list) != SFGHASH_OK )
        {
            FatalError("service_rule_map: could not add a rule to the rule-service-map\n");
        }
    }

    /* add the rule */
    if ( sflist_add_tail(list, otn) )
        FatalError("service_rule_map: could not add a rule to the service rule-list\n");
}

/*
 *  maintain a table of service maps, one for each protocol and direction,
 *  each service map maintains a list of otn's for each service it maps to a
 *  service name.
 */
static int ServiceMapAddOtn(srmm_table_t* srmm, int proto, char* servicename, OptTreeNode* otn)
{
    SFGHASH* to_srv;  /* to srv service rule map */
    SFGHASH* to_cli;  /* to cli service rule map */

    if ( !servicename )
        return 0;

    if (!otn )
        return 0;

    if ( proto == SNORT_PROTO_IP )
    {
        to_srv = srmm->ip_to_srv;
        to_cli = srmm->ip_to_cli;
    }
    else if ( proto == SNORT_PROTO_ICMP )
    {
        to_srv = srmm->icmp_to_srv;
        to_cli = srmm->icmp_to_cli;
    }
    else if ( proto == SNORT_PROTO_TCP )
    {
        to_srv = srmm->tcp_to_srv;
        to_cli = srmm->tcp_to_cli;
    }
    else if ( proto == SNORT_PROTO_UDP )
    {
        to_srv = srmm->udp_to_srv;
        to_cli = srmm->udp_to_cli;
    }
    else
    {
        to_srv = srmm->svc_to_srv;
        to_cli = srmm->svc_to_cli;
    }

    if ( OtnFlowFromClient(otn) )
    {
        ServiceMapAddOtnRaw(to_srv, servicename, otn);
    }
    else if ( OtnFlowFromServer(otn) )
    {
        ServiceMapAddOtnRaw(to_cli, servicename, otn);
    }
    else /* else add to both sides */
    {
        ServiceMapAddOtnRaw(to_srv, servicename, otn);
        ServiceMapAddOtnRaw(to_cli, servicename, otn);
    }

    return 0;
}

void fpPrintServicePortGroupSummary(srmm_table_t* srvc_pg_map)
{
    LogMessage("+--------------------------------\n");
    LogMessage("| Service-PortGroup Table Summary \n");
    LogMessage("---------------------------------\n");

    if (srvc_pg_map->ip_to_srv->count)
        LogMessage("| ip to server   : %d services\n",srvc_pg_map->ip_to_srv->count);
    if (srvc_pg_map->ip_to_cli->count)
        LogMessage("| ip to cient    : %d services\n",srvc_pg_map->ip_to_cli->count);

    if (srvc_pg_map->icmp_to_srv->count)
        LogMessage("| icmp to server : %d services\n",srvc_pg_map->icmp_to_srv->count);
    if (srvc_pg_map->icmp_to_cli->count)
        LogMessage("| icmp to cient  : %d services\n",srvc_pg_map->icmp_to_cli->count);

    if (srvc_pg_map->tcp_to_srv->count)
        LogMessage("| tcp to server  : %d services\n",srvc_pg_map->tcp_to_srv->count);
    if (srvc_pg_map->tcp_to_cli->count)
        LogMessage("| tcp to cient   : %d services\n",srvc_pg_map->tcp_to_cli->count);

    if (srvc_pg_map->udp_to_srv->count)
        LogMessage("| udp to server  : %d services\n",srvc_pg_map->udp_to_srv->count);
    if (srvc_pg_map->udp_to_cli->count)
        LogMessage("| udp to cient   : %d services\n",srvc_pg_map->udp_to_cli->count);

    if (srvc_pg_map->svc_to_srv->count)
        LogMessage("| svc to server  : %d services\n",srvc_pg_map->svc_to_srv->count);
    if (srvc_pg_map->svc_to_cli->count)
        LogMessage("| svc to cient   : %d services\n",srvc_pg_map->svc_to_cli->count);

    LogMessage("---------------------------------\n");
}

/*
 *  Scan the master otn lists and load the Service maps
 *  for service based rule grouping.
 */
int fpCreateServiceMaps(SnortConfig* sc)
{
    RuleTreeNode* rtn;
    SFGHASH_NODE* hashNode;
    OptTreeNode* otn  = NULL;
    PolicyId policyId = 0;
    unsigned int svc_idx;

    for (hashNode = sfghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = sfghash_findnext(sc->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        for ( policyId = 0;
            policyId < otn->proto_node_num;
            policyId++ )
        {
            rtn = getRtnFromOtn(otn);

            if ( rtn )
            {
                // skip builtin rules
                if ( !otn->sigInfo.text_rule )
                    continue;

                /* Not enabled, don't do the FP content */
                if ( !otn->enabled )
                    continue;

                for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
                {
                    if (ServiceMapAddOtn(sc->srmmTable, rtn->proto,
                        otn->sigInfo.services[svc_idx].service, otn))
                        return -1;
                }
            }
        }
    }

    return 0;
}

sopg_table_t* ServicePortGroupTableNew()
{
    return (sopg_table_t*)SnortAlloc(sizeof(sopg_table_t));
}

PortGroup* fpGetServicePortGroupByOrdinal(
    sopg_table_t* sopg, int proto, int dir, int16_t proto_ordinal)
{
    PortGroup* pg = NULL;

    if (proto_ordinal >= MAX_PROTOCOL_ORDINAL)
        return NULL;

    if (sopg == NULL)
        return NULL;

    switch (proto)
    {
    case SNORT_PROTO_IP:
        if (dir == TO_SERVER)
            pg = sopg->ip_to_srv[proto_ordinal];
        else
            pg = sopg->ip_to_cli[proto_ordinal];
        break;

    case SNORT_PROTO_ICMP:
        if (dir == TO_SERVER)
            pg = sopg->icmp_to_srv[proto_ordinal];
        else
            pg = sopg->icmp_to_cli[proto_ordinal];
        break;

    case SNORT_PROTO_TCP:
        if (dir == TO_SERVER)
            pg = sopg->tcp_to_srv[proto_ordinal];
        else
            pg = sopg->tcp_to_cli[proto_ordinal];
        break;

    case SNORT_PROTO_UDP:
        if (dir == TO_SERVER)
            pg = sopg->udp_to_srv[proto_ordinal];
        else
            pg = sopg->udp_to_cli[proto_ordinal];
        break;

    default:
        if (dir == TO_SERVER)
            pg = sopg->svc_to_srv[proto_ordinal];
        else
            pg = sopg->svc_to_cli[proto_ordinal];
        break;
    }

    if ( !pg )
    {
        if (dir == TO_SERVER)
            pg = sopg->svc_to_srv[proto_ordinal];
        else
            pg = sopg->svc_to_cli[proto_ordinal];
    }
    return pg;
}

