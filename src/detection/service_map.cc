//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

//-------------------------------------------------------------------------
// service map stuff
//-------------------------------------------------------------------------

static SFGHASH* alloc_srvmap()
{
    // nodes are lists,free them in sfghash_delete
    SFGHASH* p = sfghash_new(1000, 0, 0, (void (*)(void*))sflist_free);
    return p;
}

static void free_srvmap(SFGHASH* table)
{
    if ( table )
        sfghash_delete(table);
}

srmm_table_t* ServiceMapNew()
{
    srmm_table_t* table = (srmm_table_t*)snort_calloc(sizeof(srmm_table_t));

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        table->to_srv[i] = alloc_srvmap();
        table->to_cli[i] = alloc_srvmap();
    }

    return table;
}

void ServiceMapFree(srmm_table_t* table)
{
    if ( !table )
        return;

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        if ( table->to_srv[i] )
            free_srvmap(table->to_srv[i]);

        if ( table->to_cli[i] )
            free_srvmap(table->to_cli[i]);
    }

    snort_free(table);
}

//-------------------------------------------------------------------------
// service pg stuff
//-------------------------------------------------------------------------

static SFGHASH* alloc_spgmm()
{
    // 1000 rows, ascii key
    SFGHASH* p = sfghash_new(1000, 0, 0, fpDeletePortGroup);
    return p;
}

static void free_spgmm(SFGHASH* table)
{
    if ( !table )
        return;

    sfghash_delete(table);
}

srmm_table_t* ServicePortGroupMapNew()
{
    srmm_table_t* table = (srmm_table_t*)snort_calloc(sizeof(srmm_table_t));

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        table->to_srv[i] = alloc_spgmm();
        table->to_cli[i] = alloc_spgmm();
    }

    return table;
}

void ServicePortGroupMapFree(srmm_table_t* table)
{
    if ( !table )
        return;

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        if ( table->to_srv[i] )
            free_spgmm(table->to_srv[i]);

        if ( table->to_cli[i] )
            free_spgmm(table->to_cli[i]);
    }

    snort_free(table);
}

//-------------------------------------------------------------------------
// service pg stuff
//-------------------------------------------------------------------------

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
    if ( !servicename )
        return -1;

    if ( !otn )
        return -1;

    if ( proto > SNORT_PROTO_USER )
        proto = SNORT_PROTO_USER;

    SFGHASH* to_srv = srmm->to_srv[proto];
    SFGHASH* to_cli = srmm->to_cli[proto];

    if ( OtnFlowFromClient(otn) )
        ServiceMapAddOtnRaw(to_srv, servicename, otn);

    else if ( OtnFlowFromServer(otn) )
        ServiceMapAddOtnRaw(to_cli, servicename, otn);

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

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        if ( unsigned n = srvc_pg_map->to_srv[i]->count )
            LogMessage("| %s to server   : %d services\n", get_protocol_name(i), n);

        if ( unsigned n = srvc_pg_map->to_cli[i]->count )
            LogMessage("| %s to client   : %d services\n", get_protocol_name(i), n);
    }

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

//-------------------------------------------------------------------------
// sopg_table_t stuff
//-------------------------------------------------------------------------

sopg_table_t::sopg_table_t()
{
    unsigned n = (unsigned)get_protocol_count();

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; ++i )
    {
        if ( to_srv[i].size() < n )
            to_srv[i].resize(n, nullptr);

        if ( to_cli[i].size() < n )
            to_cli[i].resize(n, nullptr);
    }
    user_mode = false;
}

PortGroup* sopg_table_t::get_port_group(
    int proto, bool c2s, int16_t proto_ordinal)
{
    assert(proto < SNORT_PROTO_MAX);

    PortGroupVector& v = c2s ? to_srv[proto] : to_cli[proto];

    if ( (unsigned)proto_ordinal >= v.size() )
        return nullptr;

    return v[proto_ordinal];
}

bool sopg_table_t::set_user_mode()
{
    PortGroupVector& v1 = to_srv[SNORT_PROTO_USER];

    for ( unsigned i = 0; i < v1.size(); ++i )
    {
        if ( v1[i] )
        {
            user_mode = true;
            return true;
        }
    }
    v1 = to_cli[SNORT_PROTO_USER];

    for ( unsigned i = 0; i < v1.size(); ++i )
    {
        if ( v1[i] )
        {
            user_mode = true;
            break;
        }
    }
    return user_mode;
}

