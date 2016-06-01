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
// Author(s):   Andrew R. Baker <andrewb@sourcefire.com>

#include "signature.h"

#include <string.h>
#include <ctype.h>

#include "utils/util.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "hash/sfghash.h"
#include "parser/parser.h"
#include "main/snort_config.h"

/********************* Reference Implementation *******************************/

ReferenceNode* AddReference(
    SnortConfig* sc, ReferenceNode** head, const char* system, const char* id)
{
    ReferenceNode* node;

    if ((system == NULL) || (id == NULL) ||
        (sc == NULL) || (head == NULL))
    {
        return NULL;
    }

    /* create the new node */
    node = (ReferenceNode*)snort_calloc(sizeof(ReferenceNode));

    /* lookup the reference system */
    node->system = ReferenceSystemLookup(sc->references, system);
    if (node->system == NULL)
        node->system = ReferenceSystemAdd(sc, system, NULL);

    node->id = snort_strdup(id);

    /* Add the node to the front of the list */
    node->next = *head;
    *head = node;

    return node;
}

/* print a reference node */
void FPrintReference(FILE* fp, ReferenceNode* ref_node)
{
    if ((fp == NULL) || (ref_node == NULL))
        return;

    if (ref_node->system != NULL)
    {
        if (ref_node->system->url)
        {
            fprintf(fp, "[Xref => %s%s]", ref_node->system->url,
                ref_node->id);
        }
        else
        {
            fprintf(fp, "[Xref => %s %s]", ref_node->system->name,
                ref_node->id);
        }
    }
    else
    {
        fprintf(fp, "[Xref => %s]", ref_node->id);
    }
}

/********************* End of Reference Implementation ************************/

/********************** Reference System Implementation ***********************/

ReferenceSystemNode* ReferenceSystemAdd(
    SnortConfig* sc, const char* name, const char* url)
{
    ReferenceSystemNode** head = &sc->references;
    ReferenceSystemNode* node;

    if (name == NULL)
    {
        ErrorMessage("NULL reference system name\n");
        return NULL;
    }

    if (head == NULL)
        return NULL;

    /* create the new node */
    node = (ReferenceSystemNode*)snort_calloc(sizeof(ReferenceSystemNode));
    node->name = snort_strdup(name);

    if (url != NULL)
        node->url = snort_strdup(url);

    /* Add to the front of the list */
    node->next = *head;
    *head = node;

    return node;
}

ReferenceSystemNode* ReferenceSystemLookup(ReferenceSystemNode* head, const char* name)
{
    if (name == NULL)
        return NULL;

    while (head != NULL)
    {
        if (strcasecmp(name, head->name) == 0)
            break;

        head = head->next;
    }

    return head;
}

/****************** End of Reference System Implementation ********************/

/************************ Class/Priority Implementation ***********************/

void AddClassification(
    SnortConfig* sc, const char* type, const char* name, int priority)
{
    int max_id = 0;
    ClassType* current = sc->classifications;

    while (current != NULL)
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
    ClassType* node;

    if (sc == NULL)
        FatalError("%s(%d) Snort config is NULL.\n", __FILE__, __LINE__);

    if (type == NULL)
        return NULL;

    node = sc->classifications;

    while (node != NULL)
    {
        if (strcasecmp(type, node->type) == 0)
            break;

        node = node->next;
    }

    return node;
}

/* NOTE:  This lookup can only be done during parse time */
ClassType* ClassTypeLookupById(SnortConfig* sc, int id)
{
    ClassType* node;

    if (sc == NULL)
        FatalError("%s(%d) Snort config is NULL.\n", __FILE__, __LINE__);

    node = sc->classifications;

    while (node != NULL)
    {
        if (id == node->id)
            break;

        node = node->next;
    }

    return node;
}

void OtnRemove(SFGHASH* otn_map, OptTreeNode* otn)
{
    OtnKey key;

    if (otn == NULL)
        return;

    key.gid = otn->sigInfo.generator;
    key.sid = otn->sigInfo.id;

    if (otn_map != NULL)
        sfghash_remove(otn_map, &key);
}

void OtnFree(void* data)
{
    OptTreeNode* otn = (OptTreeNode*)data;
    unsigned int svc_idx;

    if ( !otn )
        return;

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
    for (svc_idx = 0; svc_idx < otn->sigInfo.num_services; svc_idx++)
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

SFGHASH* OtnLookupNew()
{
    return sfghash_new(10000, sizeof(OtnKey), 0, OtnFree);
}

void OtnLookupAdd(SFGHASH* otn_map, OptTreeNode* otn)
{
    int status;
    OtnKey key;

    if (otn_map == NULL)
        return;

    key.gid = otn->sigInfo.generator;
    key.sid = otn->sigInfo.id;

    status = sfghash_add(otn_map, &key, otn);

    switch (status)
    {
    case SFGHASH_OK:
        /* otn was inserted successfully */
        break;

    case SFGHASH_INTABLE:
        ParseError("duplicate rule with same gid (%u) and sid (%u)",
            key.gid, key.sid);
        break;

    default:
        FatalError("%s(%d): OtnLookupAdd() - unexpected return value "
            "from sfghash_add().\n", __FILE__, __LINE__);
    }
}

OptTreeNode* OtnLookup(SFGHASH* otn_map, uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn;
    OtnKey key;

    if (otn_map == NULL)
        return NULL;

    key.gid = gid;
    key.sid = sid;

    otn = (OptTreeNode*)sfghash_find(otn_map, &key);

    return otn;
}

void OtnLookupFree(SFGHASH* otn_map)
{
    if (otn_map == NULL)
        return;

    sfghash_delete(otn_map);
}

/***************** End of Class/Priority Implementation ***********************/

