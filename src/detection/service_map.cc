//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

    table->to_srv = alloc_srvmap();
    table->to_cli = alloc_srvmap();

    return table;
}

void ServiceMapFree(srmm_table_t* table)
{
    if ( !table )
        return;

    free_srvmap(table->to_srv);
    free_srvmap(table->to_cli);

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

    table->to_srv = alloc_spgmm();
    table->to_cli = alloc_spgmm();

    return table;
}

void ServicePortGroupMapFree(srmm_table_t* table)
{
    if ( !table )
        return;

    free_spgmm(table->to_srv);
    free_spgmm(table->to_cli);

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
    SF_LIST* list = (SF_LIST*)ghash_find(table, servicename);

    if ( !list )
    {
        list = sflist_new();
        ghash_add(table, servicename, list);
    }

    sflist_add_tail(list, otn);
}

/*
 *  maintain a table of service maps, one for each protocol and direction,
 *  each service map maintains a list of otn's for each service it maps to a
 *  service name.
 */
static int ServiceMapAddOtn(
    srmm_table_t* srmm, SnortProtocolId, const char* servicename, OptTreeNode* otn)
{
    assert(servicename and otn);

    if ( !OtnFlowFromClient(otn) )
        ServiceMapAddOtnRaw(srmm->to_cli, servicename, otn);

    if ( !OtnFlowFromServer(otn) )
        ServiceMapAddOtnRaw(srmm->to_srv, servicename, otn);

    return 0;
}

void fpPrintServicePortGroupSummary(SnortConfig* sc)
{
    LogMessage("+--------------------------------\n");
    LogMessage("| Service-PortGroup Table Summary \n");
    LogMessage("---------------------------------\n");

    if ( unsigned n = sc->spgmmTable->to_srv->count )
        LogMessage("| server   : %d services\n", n);

    if ( unsigned n = sc->spgmmTable->to_cli->count )
        LogMessage("| client   : %d services\n", n);

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
    unsigned int svc_idx;

    for (hashNode = ghash_findfirst(sc->otn_map);
        hashNode;
        hashNode = ghash_findnext(sc->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        for ( PolicyId policyId = 0;
            policyId < otn->proto_node_num;
            policyId++ )
        {
            rtn = getRtnFromOtn(otn, policyId);

            if ( rtn )
            {
                // skip builtin rules
                if ( otn->sigInfo.builtin )
                    continue;

                /* Not enabled, don't do the FP content */
                if ( !rtn->enabled() )
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
    if ( to_srv.size() < n )
        to_srv.resize(n, nullptr);

    if ( to_cli.size() < n )
        to_cli.resize(n, nullptr);
}

PortGroup* sopg_table_t::get_port_group(bool c2s, SnortProtocolId snort_protocol_id)
{
    PortGroupVector& v = c2s ? to_srv : to_cli;

    if ( snort_protocol_id >= v.size() )
        return nullptr;

    return v[snort_protocol_id];
}

