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
// Author(s):   Andrew R. Baker <andrewb@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "signature.h"

#include "hash/ghash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "treenodes.h"

using namespace snort;

/********************** Reference System Implementation ***********************/

ReferenceSystemNode* ReferenceSystemAdd(
    SnortConfig* sc, const char* name, const char* url)
{
    if ( !sc->alert_refs() )
        return nullptr;

    assert(name);

    ReferenceSystemNode* node = (ReferenceSystemNode*)snort_calloc(sizeof(*node));
    node->name = snort_strdup(name);

    if ( url )
        node->url = snort_strdup(url);

    ReferenceSystemNode** head = &sc->references;
    node->next = *head;
    *head = node;

    return node;
}

static ReferenceSystemNode* ReferenceSystemLookup(
    ReferenceSystemNode* head, const char* name)
{
    assert(name);

    while ( head )
    {
        if ( !strcasecmp(name, head->name) )
            break;

        head = head->next;
    }
    return head;
}

/********************* Reference Implementation *******************************/

void AddReference(
    SnortConfig* sc, ReferenceNode** head, const char* system, const char* id)
{
    if ( !sc->alert_refs() )
        return;

    assert(sc and head and system and id);

    /* create the new node */
    ReferenceNode* node = (ReferenceNode*)snort_calloc(sizeof(ReferenceNode));

    node->system = ReferenceSystemLookup(sc->references, system);

    if ( !node->system )
        node->system = ReferenceSystemAdd(sc, system);

    node->id = snort_strdup(id);

    node->next = *head;
    *head = node;
}

/************************ Class/Priority Implementation ***********************/

void AddClassification(
    SnortConfig* sc, const char* type, const char* name, int priority)
{
    int max_id = 0;
    ClassType* current = sc->classifications;

    while (current != nullptr)
    {
        /* dup check */
        if (strcasecmp(current->type, type) == 0)
        {
            ParseWarning(WARN_CONF,
                "Duplicate classification \"%s\""
                "found, ignoring this line", type);
            return;
        }

        if (current->id > max_id)
            max_id = current->id;

        current = current->next;
    }

    ClassType* new_node = (ClassType*)snort_calloc(sizeof(ClassType));

    new_node->type = snort_strdup(type);
    new_node->name = snort_strdup(name);
    new_node->priority = priority;
    new_node->id = max_id + 1;

    /* insert node */
    new_node->next = sc->classifications;
    sc->classifications = new_node;
}

/* NOTE:  This lookup can only be done during parse time */
ClassType* ClassTypeLookupByType(SnortConfig* sc, const char* type)
{
    assert(sc and type);
    ClassType* node = sc->classifications;

    while ( node )
    {
        if ( !strcasecmp(type, node->type) )
            break;

        node = node->next;
    }
    return node;
}

/***************** Otn Utilities ***********************/

void OtnRemove(GHash* otn_map, OptTreeNode* otn)
{
    assert(otn_map and otn);

    OtnKey key;
    key.gid = otn->sigInfo.gid;
    key.sid = otn->sigInfo.sid;

    ghash_remove(otn_map, &key);
}

void OtnFree(void* data)
{
    if ( !data )
        return;

    OptTreeNode* otn = (OptTreeNode*)data;
    OptFpList* opt_func = otn->opt_func;

    while ( opt_func )
    {
        OptFpList* tmp = opt_func;
        opt_func = opt_func->next;
        snort_free(tmp);
    }

    if ( otn->sigInfo.message )
    {
        if (!otn->generated)
            snort_free(otn->sigInfo.message);
    }
    for (unsigned svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
    {
        if (otn->sigInfo.services[svc_idx].service)
            snort_free(otn->sigInfo.services[svc_idx].service);
    }
    if (otn->sigInfo.services)
        snort_free(otn->sigInfo.services);

    ReferenceNode* ref_node = otn->sigInfo.refs;

    while ( ref_node )
    {
        ReferenceNode* tmp = ref_node;
        ref_node = ref_node->next;
        snort_free(tmp->id);
        snort_free(tmp);
    }

    if ( otn->tag )
        snort_free(otn->tag);

    if ( otn->soid )
        snort_free(otn->soid);

    /* RTN was generated on the fly.  Don't necessarily know which policy
     * at this point so go through all RTNs and delete them */
    if (otn->generated)
    {
        for (int i = 0; i < otn->proto_node_num; i++)
        {
            RuleTreeNode* rtn = deleteRtnFromOtn(otn, i);

            if ( rtn )
                snort_free(rtn);
        }
    }

    if (otn->proto_nodes)
        snort_free(otn->proto_nodes);

    if (otn->detection_filter)
        snort_free(otn->detection_filter);

    snort_free(otn->state);
    snort_free(otn);
}

GHash* OtnLookupNew()
{
    return ghash_new(10000, sizeof(OtnKey), 0, OtnFree);
}

void OtnLookupAdd(GHash* otn_map, OptTreeNode* otn)
{
    assert(otn_map);

    OtnKey key;
    key.gid = otn->sigInfo.gid;
    key.sid = otn->sigInfo.sid;

    int status = ghash_add(otn_map, &key, otn);

    if ( status == GHASH_OK )
        return;

    assert(status == GHASH_INTABLE);
    ParseError("duplicate rule with same gid (%u) and sid (%u)", key.gid, key.sid);
}

OptTreeNode* OtnLookup(GHash* otn_map, uint32_t gid, uint32_t sid)
{
    assert(otn_map);

    OtnKey key;
    key.gid = gid;
    key.sid = sid;

    OptTreeNode* otn = (OptTreeNode*)ghash_find(otn_map, &key);

    return otn;
}

OptTreeNode* GetOTN(uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn = OtnLookup(SnortConfig::get_conf()->otn_map, gid, sid);

    if ( !otn )
        return nullptr;

    if ( !getRtnFromOtn(otn) )
    {
        // If not configured to autogenerate and there isn't an RTN, meaning
        // this rule isn't in the current policy, return nullptr.
        return nullptr;
    }

    return otn;
}

void OtnLookupFree(GHash* otn_map)
{
    if ( otn_map )
        ghash_delete(otn_map);
}

