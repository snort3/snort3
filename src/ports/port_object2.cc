//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "port_object2.h"

#include "hash/hashfcn.h"
#include "log/messages.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "port_group.h"
#include "port_item.h"
#include "port_object.h"
#include "port_utils.h"

using namespace snort;

#define PO_EXTRA_RULE_CNT 25

//-------------------------------------------------------------------------
// PortObject2 - private
//-------------------------------------------------------------------------

/* This is the opposite of ntohl/htonl defines, and does the
 * swap on big endian hardware */
#ifdef WORDS_BIGENDIAN
#define SWAP_BYTES(a) \
    a = \
    ((((uint32_t)(a) & 0xFF000000) >> 24) | \
    (((uint32_t)(a) & 0x00FF0000) >> 8) | \
    (((uint32_t)(a) & 0x0000FF00) << 8) | \
    (((uint32_t)(a) & 0x000000FF) << 24))
#else
#define SWAP_BYTES(a)
#endif

static unsigned po_rule_hash_func(HashFnc* p, const unsigned char* k, int n)
{
    unsigned char* key;
    int ikey = *(const int*)k;

    /* Since the input is really an int, put the bytes into a normalized
     * order so that the hash function returns consistent results across
     * on BE & LE hardware. */
    SWAP_BYTES(ikey);

    /* Set a pointer to the key to pass to the hashing function */
    key = (unsigned char*)&ikey;

    return hashfcn_hash(p, key, n);
}

static int* RuleHashToSortedArray(GHash* rh)
{
    if ( !rh or !rh->count )
        return nullptr;

    int* ra = (int*)snort_calloc(rh->count, sizeof(int));
    int k = 0;

    for ( GHashNode* node = ghash_findfirst(rh);
        node != nullptr && k < (int)rh->count;
        node = ghash_findnext(rh) )
    {
        if ( int* prid = (int*)node->data )
            ra[k++] = *prid;
    }

    qsort(ra,rh->count,sizeof(int),integer_compare);

    return ra;
}

//-------------------------------------------------------------------------
// PortObject2 - public
//-------------------------------------------------------------------------

PortObject2* PortObject2New(int nrules)
{
    PortObject2* po = (PortObject2*)snort_calloc(sizeof(PortObject2));
    po->item_list =(SF_LIST*)sflist_new();

    if ( !po->item_list )
    {
        snort_free(po);
        return nullptr;
    }

    po->rule_hash =(GHash*)ghash_new(nrules,sizeof(int), 0,
        snort_free /* frees data - should be rule id ptrs == (int*) */);
    if ( !po->rule_hash )
    {
        sflist_free_all(po->item_list, snort_free);
        snort_free(po);
        return nullptr;
    }

    /* Use hash function defined above for hashing the key as an int. */
    ghash_set_keyops(po->rule_hash, po_rule_hash_func, memcmp);

    return po;
}

void PortObject2Free(PortObject2* po)
{
    if ( !po )
        return;

    if ( po->name )
        snort_free(po->name);

    if ( po->item_list)
        sflist_free_all(po->item_list, snort_free);

    if ( po->rule_hash)
        ghash_delete(po->rule_hash);

    if (po->port_list)
        delete po->port_list;

    if (po->group )
        PortGroup::free(po->group);

    snort_free(po);
}

void PortObject2Finalize(PortObject2* po)
{
    sflist_free_all(po->item_list, snort_free);
    po->item_list = nullptr;

    ghash_delete(po->rule_hash);
    po->rule_hash = nullptr;
}

/*
 * Dup the PortObjects Item List, Name, and RuleList->RuleHash
 */
PortObject2* PortObject2Dup(PortObject* po)
{
    PortObject2* ponew = nullptr;
    PortObjectItem* poi = nullptr;
    PortObjectItem* poinew = nullptr;
    SF_LNODE* lpos = nullptr;
    int* prid = nullptr;
    int* prule = nullptr;

    if ( !po )
        return nullptr;

    if ( !po->rule_list )
        return nullptr;

    ponew = PortObject2New(po->rule_list->count + PO_EXTRA_RULE_CNT);
    if ( !ponew )
        return nullptr;

    /* Dup the Name */
    if ( po->name )
        ponew->name = snort_strdup(po->name);
    else
        ponew->name = snort_strdup("dup");

    /* Dup the Item List */
    if ( po->item_list )
    {
        for (poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
            poi != nullptr;
            poi =(PortObjectItem*)sflist_next(&lpos) )
        {
            poinew = PortObjectItemDup(poi);

            if (!poinew)
            {
                PortObject2Free(ponew);
                return nullptr;
            }

            PortObjectAddItem( (PortObject*)ponew, poinew, nullptr);
        }
    }

    /* Dup the input rule list */
    if ( po->rule_list )
    {
        for (prid  = (int*)sflist_first(po->rule_list,&lpos);
            prid != nullptr;
            prid  = (int*)sflist_next(&lpos) )
        {
            prule = (int*)snort_calloc(sizeof(int));
            *prule = *prid;

            if ( ghash_add(ponew->rule_hash, prule, prule) != GHASH_OK )
            {
                snort_free(prule);
            }
        }
    }

    return ponew;
}

void PortObject2Iterate(PortObject2* po, PortObjectIterator f, void* pv)
{
    PortObjectItem* poi;
    SF_LNODE* cursor;

    for ( poi = (PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi;
        poi = (PortObjectItem*)sflist_next(&cursor) )
    {
        if ( !poi->any() )
        {
            for ( int i = poi->lport; i<= poi->hport; i++ )
                f(i, pv);
        }
    }
}

/* Dup and append rule list numbers from pob to poa */
PortObject2* PortObject2AppendPortObject(PortObject2* poa, PortObject* pob)
{
    SF_LNODE* lpos;

    for ( int* prid = (int*)sflist_first(pob->rule_list,&lpos);
        prid!= nullptr;
        prid = (int*)sflist_next(&lpos) )
    {
        int* prid2 = (int*)snort_calloc(sizeof(int));
        *prid2 = *prid;

        if ( ghash_add(poa->rule_hash,prid2,prid2) != GHASH_OK )
            snort_free(prid2);
    }
    return poa;
}

/* Dup and append rule list numbers from pob to poa */
PortObject2* PortObject2AppendPortObject2(PortObject2* poa, PortObject2* pob)
{
    for (GHashNode* node = ghash_findfirst(pob->rule_hash);
        node!= nullptr;
        node = ghash_findnext(pob->rule_hash) )
    {
        int* prid = (int*)node->data;

        if ( !prid )
            continue;

        int* prid2 = (int*)snort_calloc(sizeof(int));
        *prid2 = *prid;

        if ( ghash_add(poa->rule_hash,prid2,prid2) != GHASH_OK )
            snort_free(prid2);
    }
    return poa;
}

/*
 *  Append Ports and Rules from pob to poa
 */
PortObject2* PortObjectAppendEx2(PortObject2* poa, PortObject* pob)
{
    // LogMessage("PortObjectAppendEx: appending ports\n");
    if ( !PortObjectAppend((PortObject*)poa, pob) )
        return nullptr;

    //  LogMessage("PortObjectAppendEx: appending rules\n");
    if ( !PortObject2AppendPortObject(poa, pob) )
        return nullptr;

    return poa;
}

void PortObject2PrintPorts(PortObject2* po)
{
    PortObjectItem* poi = nullptr;
    SF_LNODE* pos = nullptr;
    int bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject ");

    if ( po->name )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ", po->name);
    }

    SnortSnprintfAppend(po_print_buf, bufsize,
        " Id:%d  Ports:%u Rules:%u\n {\n Ports [",
        po->id, po->item_list->count, po->rule_hash->count);

    if ( PortObjectHasAny( (PortObject*)po) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != nullptr;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, " ]\n }\n");
    LogMessage("%s", po_print_buf);
}

void PortObject2PrintEx(PortObject2* po,
    void (* print_index_map)(int index, char* buf, int bufsize) )
{
    PortObjectItem* poi = nullptr;
    SF_LNODE* pos = nullptr;
    int k=0;
    int* rlist = nullptr;
    unsigned int i;
    int bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject2 ");

    if ( po->name )
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ",po->name);

    SnortSnprintfAppend(po_print_buf, bufsize, " Id:%d  Ports:%u Rules:%u PortUsageCnt=%d\n {\n",
        po->id, po->item_list->count, po->rule_hash->count, po->port_cnt);

    SnortSnprintfAppend(po_print_buf, bufsize, "  Ports [\n  ");

    if ( PortObjectHasAny( (PortObject*)po) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != nullptr;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n");

    rlist = RuleHashToSortedArray(po->rule_hash);
    if (!rlist )
        return;

    SnortSnprintfAppend(po_print_buf, bufsize, "  Rules [ \n ");
    for (i=0; i<po->rule_hash->count; i++)
    {
        if ( print_index_map )
        {
            print_index_map(rlist[i], po_print_buf, bufsize);
        }
        else
        {
            SnortSnprintfAppend(po_print_buf, bufsize, " %d", rlist[i]);
        }
        k++;
        if ( k == 25 )
        {
            k=0;
            SnortSnprintfAppend(po_print_buf, bufsize, " \n ");
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n }\n");

    LogMessage("%s", po_print_buf);

    snort_free(rlist);
}

void PortObject2Print(PortObject2* po)
{
    PortObject2PrintEx(po, rule_index_map_print_index);
}

