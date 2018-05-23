//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "service_map.h"

#include <cassert>

#include "hash/ghash.h"
#include "ips_options/ips_flow.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "utils/sflsq.h"
#include "utils/util.h"

#include "fp_create.h"
#include "treenodes.h"

using namespace snort;

//-------------------------------------------------------------------------
// service map stuff
//-------------------------------------------------------------------------

static GHash* alloc_srvmap()
{
    // nodes are lists,free them in ghash_delete
    GHash* p = ghash_new(1000, 0, 0, (void (*)(void*))sflist_free);
    return p;
}

static void free_srvmap(GHash* table)
{
    if ( table )
        ghash_delete(table);
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

static void delete_pg(void* pv)
{ PortGroup::free((PortGroup*)pv); }

static GHash* alloc_spgmm()
{
    // 1000 rows, ascii key
    GHash* p = ghash_new(1000, 0, 0, delete_pg);
    return p;
}

static void free_spgmm(GHash* table)
{
    if ( !table )
        return;

    ghash_delete(table);
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
static void ServiceMapAddOtnRaw(GHash* table, const char* servicename, OptTreeNode* otn)
{
    SF_LIST* list;

    list = (SF_LIST*)ghash_find(table, servicename);

    if ( !list )
    {
        /* create the list */
        list = sflist_new();
        if ( !list )
            FatalError("service_rule_map: could not create a  service rule-list\n");

        /* add the service list to the table */
        if ( ghash_add(table, servicename, list) != GHASH_OK )
        {
            FatalError("service_rule_map: could not add a rule to the rule-service-map\n");
        }
    }

    /* add the rule */
    sflist_add_tail(list, otn);
}

/*
 *  maintain a table of service maps, one for each protocol and direction,
 *  each service map maintains a list of otn's for each service it maps to a
 *  service name.
 */
static int ServiceMapAddOtn(
    srmm_table_t* srmm, SnortProtocolId proto_id, const char* servicename, OptTreeNode* otn)
{
    assert(servicename and otn);

    if ( proto_id > SNORT_PROTO_USER )
        proto_id = SNORT_PROTO_USER;

    GHash* to_srv = srmm->to_srv[proto_id];
    GHash* to_cli = srmm->to_cli[proto_id];

    if ( !OtnFlowFromClient(otn) )
        ServiceMapAddOtnRaw(to_cli, servicename, otn);

    if ( !OtnFlowFromServer(otn) )
        ServiceMapAddOtnRaw(to_srv, servicename, otn);

    return 0;
}

void fpPrintServicePortGroupSummary(SnortConfig* sc)
{
    LogMessage("+--------------------------------\n");
    LogMessage("| Service-PortGroup Table Summary \n");
    LogMessage("---------------------------------\n");

    for ( int i = SNORT_PROTO_IP; i < SNORT_PROTO_MAX; i++ )
    {
        if ( unsigned n = sc->spgmmTable->to_srv[i]->count )
            LogMessage("| %s to server   : %d services\n", sc->proto_ref->get_name(i), n);

        if ( unsigned n = sc->spgmmTable->to_cli[i]->count )
            LogMessage("| %s to client   : %d services\n", sc->proto_ref->get_name(i), n);
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
    GHashNode* hashNode;
    OptTreeNode* otn  = nullptr;
    PolicyId policyId = 0;
    unsigned int svc_idx;

    for (hashNode = ghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = ghash_findnext(sc->otn_map))
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
                if ( otn->sigInfo.builtin )
                    continue;

                /* Not enabled, don't do the FP content */
                if ( !otn->enabled )
                    continue;

                for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
                {
                    const char* svc = otn->sigInfo.services[svc_idx].service;

                    if ( ServiceMapAddOtn(sc->srmmTable, rtn->snort_protocol_id, svc, otn) )
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

sopg_table_t::sopg_table_t(unsigned n)
{
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
    SnortProtocolId proto_id, bool c2s, SnortProtocolId snort_protocol_id)
{
    assert(proto_id < SNORT_PROTO_MAX);

    PortGroupVector& v = c2s ? to_srv[proto_id] : to_cli[proto_id];

    if ( snort_protocol_id >= v.size() )
        return nullptr;

    return v[snort_protocol_id];
}

bool sopg_table_t::set_user_mode()
{
    for ( auto* p : to_srv[SNORT_PROTO_USER] )
    {
        if ( p )
        {
            user_mode = true;
            return true;
        }
    }

    for ( auto* p : to_cli[SNORT_PROTO_USER] )
    {
        if ( p )
        {
            user_mode = true;
            break;
        }
    }
    return user_mode;
}

