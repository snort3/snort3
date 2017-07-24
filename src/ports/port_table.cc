//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "port_table.h"

#include <memory>

#include "hash/sfhashfcn.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "port_utils.h"

#define PTBL_LRC_DEFAULT 10
#define PO_INIT_ID 1000000
#define PO_HASH_TBL_ROWS 10000

//-------------------------------------------------------------------------
// PortTable - private - plx
//-------------------------------------------------------------------------

// plx_t is a variable sized array of pointers
struct plx_t
{
    int n;
    void** p;
};

static plx_t* plx_new(void* pv_array[], int n)
{
    if (!pv_array || n < 0)
        return nullptr;

    plx_t* p = (plx_t*)snort_calloc(sizeof(plx_t));
    p->p = (void**)snort_calloc(n, sizeof(void*));
    p->n = n;

    for ( int i = 0; i < n; i++ )
        p->p[i] = pv_array[i];

    return p;
}

static void plx_free(void* p)
{
    plx_t* plx = (plx_t*)p;

    if ( !plx )
        return;

    if ( plx->p )
        snort_free(plx->p);

    snort_free(p);
}

#ifdef DEBUG_MSGS
static void plx_print(plx_t* p)
{
    DEBUG_WRAP
    (
        DebugFormat(DEBUG_PORTLISTS, "plx-n=%d\n", p->n);
        for ( int i = 0; i < p->n; i++ )
            DebugFormat(DEBUG_PORTLISTS, "plx[%d]=%p\n", i, p->p[i]);
    );
}
#endif

static unsigned plx_hash(SFHASHFCN* p, unsigned char* d, int)
{
    unsigned hash = p->seed;
    plx_t* plx = *(plx_t**)d;

    for ( int i = 0; i < plx->n; i++ )
    {
        unsigned char* pc_ptr = (unsigned char*)&plx->p[i];

        for ( unsigned k = 0; k < sizeof(void*); k++ )
        {
            hash *=  p->scale;
            hash +=  pc_ptr[k];
        }
    }
    return hash ^ p->hardener;
}

/* for sorting an array of pointers */
static inline int p_keycmp(const void* a, const void* b)
{
    if ( *(unsigned long**)a < *(unsigned long**)b )
        return -1;

    if ( *(unsigned long**)a > *(unsigned long**)b )
        return 1;

    return 0; /* they are equal */
}

/*
   Hash Key Comparisons for treating plx_t types as Keys

   return values memcmp style

   this only needs to produce 0 => exact match, otherwise not.
   -1, and +1 are not strictly needed, they could both return
   a non zero value for the purposes of hashing and searching.
*/
static int plx_keycmp(const void* a, const void* b, size_t)
{
    plx_t* pla = *(plx_t**)a;
    plx_t* plb = *(plx_t**)b;

    if ( pla->n < plb->n )
        return -1;

    if ( pla->n > plb->n )
        return 1;

    for ( int i = 0; i < pla->n; i++ )
    {
        if ( int cmp = p_keycmp(&pla->p[i], &plb->p[i]) )
            return cmp;
    }

    return 0; /* they are equal */
}

//-------------------------------------------------------------------------
// PortTable - private - other
//-------------------------------------------------------------------------

/*
   Hash Key Comparisons for treating PortObjects as Keys

   return values memcmp style
*/
static int PortObject_keycmp(const void* a, const void* b, size_t)
{
    return !PortObjectEqual(*(PortObject**)a, *(PortObject**)b);
}

/*
    Hash routine for hashing PortObjects as Keys

    p - SFHASHFCN *
    d - PortObject *
    n = 4 bytes (sizeof*) - not used

   Don't use this for type=ANY port objects
*/
static unsigned PortObject_hash(SFHASHFCN* p, unsigned char* d, int)
{
    unsigned hash = p->seed;
    PortObject* po = *(PortObject**)d;
    SF_LNODE* pos;

    /* hash up each item */
    for ( PortObjectItem* poi = (PortObjectItem*)sflist_first(po->item_list, &pos);
        poi != nullptr;
        poi = (PortObjectItem*)sflist_next(&pos) )
    {
        if ( poi->any() )
            continue;

        hash *=  p->scale;
        hash +=  poi->lport & 0xff;
        hash *=  p->scale;
        hash +=  (poi->lport >> 8) & 0xff;

        hash *=  p->scale;
        hash +=  poi->hport & 0xff;
        hash *=  p->scale;
        hash +=  (poi->hport >> 8) & 0xff;
    }
    return hash ^ p->hardener;
}

/*
 * Merge multiple PortObjects into a final PortObject2,
 * this merges ports and rules.
 *
 *  merge po's in pol, find a previous instance add it.
 *
 *  This is done as follows:
 *  1) check if it's in the plx table-mhashx, this uses the list of
 *  addresses of the Input PortObjects as it's key, not the ports.
 *  This is quick and does not require assembling/merging the port
 *  objects into a PortObject2 1st.
 *  2) if found were done, otherwise
 *  3) make a merged PortObject2
 *  4) Try adding the PortObject2 to it's table - mhash
 *     a) if it adds go on, else
 *     b) if it's already in the table
 *        1) get the one in the table
 *        2) add any ports in the just created one
 *        3) free the one just created
 *  5) Create a plx object
 *  6) Add the plx object to the plx Table
 *      1) if it's already in the object - fail this contradicts 1)
 *  7) return the create PortObject2, or the one retrieved from the
 *     PortObject table.
 *
 * pol    - list of input PortObject pointers
 * pol_cnt- count in 'pol'
 * mhash  - stores the merged ports, using the merged port objects port list as a key.
 * mhashx - stores plx keys, and PortObject2 *'s as data for the final merged port objects,
 *          the plx keys provide a quicker way to compare port lists to ensure if two ports
 *          are using the same set of rules (port objects).
 * plx    - key to use to lookup and store the merged port object
 *
 * mhash and mhashx reference the same port objects as data, but use different keys for lookup
 * purposes. Once we perform a merge we store the results, using the 'plx' as the key for future
 * lookup.
 */
static PortObject2* _merge_N_pol(
    SFGHASH* mhash, SFGHASH* mhashx,
    SF_LIST* plx_list, void** pol,
    int pol_cnt, plx_t* plx)
{
    PortObject2* ponew;
    PortObject2* pox;
    plx_t* plx_tmp;
    int stat;

    /*
    * Check for the merged port object in the plx table
    */
    DebugFormat(DEBUG_PORTLISTS, "++++n=%d sfghash_find-mhashx\n", pol_cnt);
    ponew = (PortObject2*)sfghash_find(mhashx, &plx);

    if ( ponew )
    {
        DebugFormat(DEBUG_PORTLISTS, "n=%d ponew found in mhashx\n", pol_cnt);
        return ponew;
    }
    DebugFormat(DEBUG_PORTLISTS, "n=%d posnew not found in mhashx\n", pol_cnt);

    /*
    *  Merge the port objects together - ports and rules
    */

    /* Dup the 1st port objects rules and ports */
    ponew = PortObject2Dup( (PortObject*)pol[0]);
    if ( !ponew )
    {
        FatalError("Could not Dup2\n");
    }

    /* Merge in all the other port object rules and ports */
    if ( pol_cnt > 1 )
    {
        for ( int i = 1; i < pol_cnt; i++ )
        {
            DebugFormat(DEBUG_PORTLISTS, "*** %u rules in object %d\n",
                ((PortObject*)pol[i])->rule_list->count, i);
            PortObjectAppendEx2(ponew, (PortObject*)pol[i]);
            DebugFormat(DEBUG_PORTLISTS, "*** merged port-object[%d], %u rules\n",
                i, ponew->rule_hash->count);
        }
        PortObjectNormalize( (PortObject*)ponew);
    }

    DebugFormat(DEBUG_PORTLISTS, "*** merged %d port objects, %u rules\n",
        pol_cnt, ponew->rule_hash->count);
    DebugMessage(DEBUG_PORTLISTS, "*** merged ponew - follows: \n");
    // PortObjectPrint2(ponew);

    /*
    * Add the Merged PortObject2 to the PortObject2 hash table
    * keyed by ports.
    */
    DebugFormat(DEBUG_PORTLISTS, "n=%d sfghash_add-mhash\n", pol_cnt);
    stat =sfghash_add(mhash, &ponew, ponew);
    if ( stat != SFGHASH_OK )
    {
        /* This is possible since PLX hash on a different key */
        if ( stat == SFGHASH_INTABLE )
        {
            DebugFormat(DEBUG_PORTLISTS, "n=%d sfghash_add-mhash ponew in table\n", pol_cnt);
            DebugFormat(DEBUG_PORTLISTS, "n=%d sfghash_find-mhash ponew\n", pol_cnt);
            pox = (PortObject2*)sfghash_find(mhash, &ponew);
            if ( pox )
            {
                PortObject2AppendPortObject2(pox, ponew);
                DebugMessage(DEBUG_PORTLISTS, "sfportobject.c: merge_N_pol() SFGHASH_INTABLE\n");
                PortObject2Free(ponew);
                ponew = pox;
                DebugFormat(DEBUG_PORTLISTS,
                    "n=%d sfghash_find-mhash ponew found, new rules merged\n", pol_cnt);
            }
            else
            {
                FatalError("mhash add/find error n=%d\n", pol_cnt);
            }
        }
        else
        {
            FatalError("Could not add ponew to hash table- error\n");
        }
    }

    DebugFormat(DEBUG_PORTLISTS, "***%d ports merged object added to mhash  table\n", pol_cnt);

    /*
    * Create a plx node and add it to plx table
    * as the key with the merged port object as the data
    */
    plx_tmp = plx_new(pol, pol_cnt);
    if (!plx_tmp)
    {
        FatalError("plx_new: memory alloc error\n");
    }
    sflist_add_head(plx_list, (void*)plx_tmp);

    /*
     * Add the plx node to the PLX hash table
     */
    DebugFormat(DEBUG_PORTLISTS, "n=%d sfghash_add-mhashx\n", pol_cnt);
    stat = sfghash_add(mhashx, &plx_tmp, ponew);
    if ( stat != SFGHASH_OK )
    {
        if ( stat == SFGHASH_INTABLE )
        {
            FatalError("Could not add merged plx to PLX HASH table-INTABLE\n");
        }
        else
        {
            FatalError("Could not add merged plx to PLX HASH table\n");
        }
    }

    DebugFormat(DEBUG_PORTLISTS, "Added-%d Merged Rule Groups to PLX HASH\n", pol_cnt);

    /*
    *  Validate hash table entry
    */
    if ( sfghash_find(mhashx, &plx_tmp) != ponew )
    {
        FatalError("Find after add failed on PLX HASH table key\n");
    }

    return ponew;
}

/*
 * Merge Input Port Objects into rule collections that are particular to
 * each port.  We store the results as objects and point to these in the
 * pt_port_object[MAX_PORTS] array.
 *
 * We use plx_t types to manage tracking and testing for merged large
 * rule groups, and merged small port groups.
 *
 * mhash   - table of merged port objects ( built and used here )
 * mhashx  - table of plx_t objects ( built and used here )
 * pol     - list of input port objects touching the current port
 * pol_cnt - number of port objects in port list
 * lcnt    - large rule count
 *
 */
static PortObject2* PortTableCompileMergePortObjectList2(
    SFGHASH* mhash, SFGHASH* mhashx, SF_LIST* plx_list,
    PortObject* pol[], int pol_cnt, unsigned int lcnt)
{
    std::unique_ptr<void*[]> upA(new void*[SFPO_MAX_LPORTS]);
    std::unique_ptr<void*[]> upB(new void*[SFPO_MAX_LPORTS]);

    void** polarge = upA.get();
    void** posmall = upB.get();

    int nlarge = 0;
    int nsmall = 0;

    /*
    * Classify PortObjects as large or small based on rule set size
    * and copy them into separate lists
    */
    for ( int i = 0; i < pol_cnt; i++ )
    {
        if ( pol[i]->rule_list->count >= (unsigned)lcnt )
        {
            if ( nlarge < SFPO_MAX_LPORTS )
                polarge[ nlarge++ ] = (void*)pol[i];
        }
        else
        {
            if ( nsmall < SFPO_MAX_LPORTS )
                posmall[ nsmall++ ] = (void*)pol[i];
        }
    }

    DebugFormat(DEBUG_PORTLISTS,
        "*** %d small rule groups, %d large rule groups\n", nsmall, nlarge);

    /*
    * Sort the pointers to the input port objects so
    * we always get them in the same order for key comparisons
    */
    if ( nlarge > 1 )
        qsort(polarge, nlarge, sizeof(void*), p_keycmp);

    if ( nsmall > 1 )
        qsort(posmall, nsmall, sizeof(void*), p_keycmp);

    DEBUG_WRAP
    (
        for ( int i = 0; i < nsmall; i++ )
            DebugFormat(DEBUG_PORTLISTS, "posmall[%d]=%p\n", i, posmall[i]);

        for ( int i = 0; i < nlarge; i++)
            DebugFormat(DEBUG_PORTLISTS, "polarge[%d]=%p\n", i, polarge[i]);
    );

    /*
    * Setup plx_t representation of port list pointers
    */
    plx_t plx_small;
    plx_t plx_large;

    plx_small.n = nsmall;
    plx_small.p = (void**)&posmall[0];

    plx_large.n = nlarge;
    plx_large.p = (void**)&polarge[0];

#ifdef DEBUG_MSGS
    if ( nlarge )
    {
        DebugMessage(DEBUG_PORTLISTS, "large ");
        plx_print(&plx_large);
    }
    if ( nsmall )
    {
        DebugMessage(DEBUG_PORTLISTS, "small ");
        plx_print(&plx_small);
    }
#endif

    PortObject2* ponew = nullptr;
    PortObject2* posnew = nullptr;

    /*
    * Merge Large PortObjects
    */
    if ( nlarge )
    {
        DebugFormat(DEBUG_PORTLISTS, "***nlarge=%d \n", nlarge);
        ponew =  _merge_N_pol(mhash, mhashx, plx_list, polarge, nlarge, &plx_large);
    }

    /*
    * Merge Small PortObjects
    */
    if ( nsmall )
    {
        DebugFormat(DEBUG_PORTLISTS, "***nsmall=%d \n", nsmall);
        posnew =  _merge_N_pol(mhash, mhashx, plx_list, posmall, nsmall, &plx_small);
    }
    /*
    * Merge Large and Small (rule groups) PortObject2's together
    * append small port object rule sets to the large port objects,
    * remove the large port objects ports from the smaller port objects
    */
    if ( nlarge && nsmall )
    {
        DebugMessage(DEBUG_PORTLISTS, "*** appending small rules to larger rule group\n");
        if (ponew != posnew)
        {
            /* Append small port object, just the rules */
            PortObject2AppendPortObject2(ponew, posnew);

            /* Remove Ports in ponew from posnew */
            PortObjectRemovePorts( (PortObject*)posnew, (PortObject*)ponew);
        }

        DebugMessage(DEBUG_PORTLISTS, "*** final - using small+large rule group \n");
    }
    else if ( nsmall )
    {
        /* Only a small port object */
        ponew = posnew;

        DebugMessage(DEBUG_PORTLISTS, "*** final - using small rule group only \n");
    }
    else if ( nlarge )
    {
        /*
         * The large rule group port object is already set to ponew
         */
    }

    return ponew;
}

/*
 *
 *  Verify all rules in 'po' list are in 'po2' hash
 *
 *  return  0 - OK
 *         !0 - a rule in po is not in po2
 */
static int _po2_include_po_rules(PortObject2* po2, PortObject* po)
{
    SF_LNODE* rpos;

    /* get each rule in po */
    for ( int* pid = (int*)sflist_first(po->rule_list, &rpos);
        pid;
        pid = (int*)sflist_next(&rpos) )
    {
        /* find it in po2 */
        int* id = (int*)sfghash_find(po2->rule_hash, pid);

        /* make sure it's in po2 */
        if ( !id )
            return 1; /* error */
    }

    return 0;
}

static int PortTableCompileMergePortObjects(PortTable* p)
{
    DebugMessage(DEBUG_PORTLISTS, "***\n***Merging PortObjects->PortObjects2\n***\n");

    std::unique_ptr<PortObject*[]> upA(new PortObject*[SFPO_MAX_LPORTS]);
    PortObject** pol = upA.get();

    // Create a Merged Port Object Table - hash by ports, no user keys, don't free data
    SFGHASH* mhash = sfghash_new(PO_HASH_TBL_ROWS, sizeof(PortObject*), 0, 0);

    /* Setup hashing function and key comparison function */
    sfhashfcn_set_keyops(mhash->sfhashfcn, PortObject_hash, PortObject_keycmp);

    p->pt_mpo_hash = mhash;

    // Create a Merged Port Object Table - hash by pointers, no user keys, don't free data
    SFGHASH* mhashx = sfghash_new(PO_HASH_TBL_ROWS, sizeof(plx_t*), 0, 0);

    /* Setup hashing function and key comparison function */
    sfhashfcn_set_keyops(mhashx->sfhashfcn, plx_hash, plx_keycmp);

    p->pt_mpxo_hash = mhashx;

    DebugFormat(DEBUG_PORTLISTS,
        "***\n*** PortList-Merging, Large Rule groups must have %d rules\n", p->pt_lrc);

    SF_LIST* plx_list = sflist_new();

    /*
     *  For each port, merge rules from all port objects that touch the port
     *  into an optimal object, that may be shared with other ports.
     */
    int id = PO_INIT_ID;

    for ( int i = 0; i < SFPO_MAX_PORTS; i++ )
    {
        /* Build a list of port objects touching port 'i' */
        int pol_cnt = 0;
        PortObject* po;
        SF_LNODE* lpos;

        for (po = (PortObject*)sflist_first(p->pt_polist, &lpos);
            po;
            po = (PortObject*)sflist_next(&lpos) )
        {
            if ( PortObjectHasPort (po, i) )
            {
                if ( pol_cnt < SFPO_MAX_LPORTS )
                {
                    pol[ pol_cnt++ ] = po;
                }
            }
        }
        p->pt_port_object[i] = 0;

        if ( !pol_cnt )
        {
            //port not contained in any PortObject
            continue;
        }

        DEBUG_WRAP(DebugFormat(DEBUG_PORTLISTS,
            "*** merging list for port[%d] \n", i); fflush(stdout); );

        /* merge the rules into an optimal port object */
        p->pt_port_object[i] =
            PortTableCompileMergePortObjectList2(
                mhash, mhashx, plx_list, pol, pol_cnt, p->pt_lrc);

        if ( !p->pt_port_object[i] )
        {
            FatalError(" Could not merge PorObjectList on port %d\n", i);
        }

        /* give the new compiled port object an id of its own */
        p->pt_port_object[i]->id = id++;

        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS, "\n"); fflush(stdout); );
    }

    /*
     * Normalize the Ports so they indicate only the ports that
     * reference the composite port object
     */

    /* 1st- Setup bitmasks for collecting ports */
    for (SFGHASH_NODE* node=sfghash_findfirst(mhashx);
        node;
        node=sfghash_findnext(mhashx) )
    {
        PortObject2* poa = (PortObject2*)node->data;

        if ( !poa )
            continue;

        if (!poa->port_list)
        {
            poa->port_list = new PortBitSet;

            if ( !poa->port_list)
                FatalError("Memory error in PortTableCompile\n");
        }
    }

    /* Count how many ports each final port-object is used on */
    for ( int i = 0; i < SFPO_MAX_PORTS; i++ )
    {
        PortObject2* poa;
        poa = p->pt_port_object[i];
        if (poa)
        {
            poa->port_cnt++;

            if ( poa->port_list )
                poa->port_list->set(i);

            else
                FatalError("NULL po->port_list in po on port %d\n", i);
        }
    }

    /* Process Port map and print final port-object usage stats */
    for (SFGHASH_NODE* node=sfghash_findfirst(mhashx);
        node;
        node=sfghash_findnext(mhashx) )
    {
        PortObject2* po = (PortObject2*)node->data;

        if ( !po )
            FatalError("MergePortOBject-NormalizePorts -NULL po\n");

        if ( !po->port_cnt ) /* port object is not used ignore it */
            continue;

        if ( !po->port_list )
        {
            //FatalError("MergePortOBject-NormalizePorts -NULL po->port_list\n");
            continue;
        }

        PortBitSet parray;

        /* Convert the port_list bits to a char array */
        for ( int i = 0; i < SFPO_MAX_PORTS; i++ )
            parray[ i ] = po->port_list->test(i);

        /* Release bit buffer for each port object */
        if ( po->port_list )
        {
            delete po->port_list;
            po->port_list = nullptr;
        }

        /* Build a PortObjectItem list from the char array */
        SF_LIST* plist = PortObjectItemListFromBits(parray, SFPO_MAX_PORTS);

        if ( !plist )
        {
            FatalError("MergePortObjects: No PortObjectItems in portobject\n");
        }

        /* free the original list */
        sflist_free_all(po->item_list, snort_free);

        /* set the new list - this is a list of port items for this port object */
        po->item_list = plist;

        DebugFormat(DEBUG_PORTLISTS, "port-object id = %d, port cnt = %d\n", po->id,
            po->port_cnt);
    }

    sflist_free_all(plx_list, plx_free);
    return 0;
}

// consistency check - part 1
// make sure each port is only in one composite port object

static void PortTableConsistencyCheck(PortTable* p)
{
    std::unique_ptr<char[]> upA(new char[SFPO_MAX_PORTS]);
    char* parray = upA.get();
    memset(parray, 0, SFPO_MAX_PORTS);

    for ( SFGHASH_NODE* node=sfghash_findfirst(p->pt_mpo_hash);
        node;
        node=sfghash_findnext(p->pt_mpo_hash) )
    {
        PortObject2* po = (PortObject2*)node->data;

        if ( !po )
        {
            FatalError("PortObject consistency Check failed, hash table problem\n");
        }

        if ( !po->port_cnt ) /* port object is not used ignore it */
            continue;

        for ( int i = 0; i < SFPO_MAX_PORTS; i++ )
        {
            if ( PortObjectHasPort( (PortObject*)po, i) )
            {
                if ( parray[i] )
                {
                    FatalError("PortTableCompile: failed consistency check, "
                        "multiple objects reference port %d\n", i);
                }
                parray[i] = 1;
            }
        }
    }

    DebugMessage(DEBUG_PORTLISTS,
        "***\n***Port Table Compiler Consistency Check Phase-I Passed !\n");
}

// consistency check - part 2
/*
* This phase checks the Input port object rules/ports against
* the composite port objects.
*
* For each input object
*    check that each port it reference has all of the rules
*    referenced to that port in the composite object
*/
static void PortTableConsistencyCheck2(PortTable* p)
{
    SF_LNODE* pos;
    PortObject2* lastpo = nullptr;

    for ( PortObject* ipo = (PortObject*)sflist_first(p->pt_polist, &pos);
        ipo;
        ipo = (PortObject*)sflist_next(&pos) )
    {
        /*
         * for each port in this object get the composite port object
         * assigned to that port and verify all of the input objects rules
         * are in the composite object.  This verifies all rules are applied
         * to the originally intended port.
         */
        SF_LNODE* ipos;

        for ( PortObjectItem* poi = (PortObjectItem*)sflist_first(ipo->item_list, &ipos);
            poi;
            poi = (PortObjectItem*)sflist_next(&ipos) )
        {
            if ( poi->any() )
                continue;

            for ( int i = poi->lport; i <= poi->hport; i++ )
            {
                /* small optimization*/
                if ( lastpo != p->pt_port_object[i] )
                {
                    if ( _po2_include_po_rules(p->pt_port_object[i], ipo) )
                    {
                        FatalError("InputPortObject<->CompositePortObject "
                            "consistency Check II failed\n");
                    }
                    lastpo = p->pt_port_object[i];
                }
            }
        }
    }

    DebugMessage(DEBUG_PORTLISTS,
        "***\n***Port Table Compiler Consistency Check Phase-II Passed !!!"
        " - Good to go Houston\n****\n");
}

//-------------------------------------------------------------------------
// PortTable - public
//-------------------------------------------------------------------------

PortTable* PortTableNew()
{
    PortTable* p = (PortTable*)snort_calloc(sizeof(PortTable));
    p->pt_polist = sflist_new();

    if (!p->pt_polist )
    {
        snort_free(p);
        return 0;
    }

    p->pt_lrc = PTBL_LRC_DEFAULT; /* 10 rules, user should really control these */
    p->pt_optimize = 1; /* if disabled, only one merged rule group is used */

    return p;
}

void PortTableFree(PortTable* p)
{
    if (!p)
        return;

    if (p->pt_polist)
    {
        sflist_free_all(p->pt_polist, PortObjectFree);
    }
    if (p->pt_mpo_hash)
    {
        PortObject2* po;

        for ( SFGHASH_NODE* node = sfghash_findfirst(p->pt_mpo_hash);
            node;
            node = sfghash_findnext(p->pt_mpo_hash) )
        {
            po = (PortObject2*)node->data;
            PortObject2Free(po);
        }
        sfghash_delete(p->pt_mpo_hash);
    }
    if (p->pt_mpxo_hash)
    {
        sfghash_delete(p->pt_mpxo_hash);
    }

    snort_free(p);
}

// FIXIT-P we should be able to free pt_mpo_hash early too
void PortTableFinalize(PortTable* p)
{
    sfghash_delete(p->pt_mpxo_hash);
    p->pt_mpxo_hash = nullptr;
}

PortObject* PortTableFindInputPortObjectPorts(PortTable* pt, PortObject* pox)
{
    if ( !pt or !pox )
        return nullptr;

    SF_LNODE* lpos;

    for ( PortObject* po = (PortObject*)sflist_first(pt->pt_polist, &lpos);
        po!=0;
        po = (PortObject*)sflist_next(&lpos) )
    {
        if ( PortObjectEqual(po, pox) )
        {
            return po;
        }
    }
    return nullptr;
}

/*
    Add Users PortObjects to the Table
    We save the users port object, so it's no longer the users.
*/
int PortTableAddObject(PortTable* p, PortObject* po)
{
    SF_LNODE* lpos;

    /* Search for the Port Object in the input list, by address */
    for ( PortObject* pox = (PortObject*)sflist_first(p->pt_polist, &lpos);
        pox!=0;
        pox = (PortObject*)sflist_next(&lpos) )
    {
        if ( pox == po )
            return 0;   // already in list - just return
    }

    /* Save the users port object, if not already in the list */
    sflist_add_tail(p->pt_polist, po);
    return 0;
}

/*
* Compile the PortTable
*
* This builds a set of Port+Rule objects that are in some way an optimal
* set of objects to indicate which rules to apply to which ports. Since
* these groups are calculated consistency checking is done with the finished
* objects.
*/
int PortTableCompile(PortTable* p)
{
    /*
    *  If not using an optimized Table use the rule_index_map in parser.c
    */
    if ( !p->pt_optimize )
        return 0;

    DebugMessage(DEBUG_PORTLISTS, "#PortTableCompile: Compiling Port Array Lists\n");

    if ( PortTableCompileMergePortObjects(p) )
    {
        FatalError("Could not create PortArryayLists\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS, "Done\n"); fflush(stdout); );

    PortTableConsistencyCheck(p);
    PortTableConsistencyCheck2(p);

    return 0;
}

void PortTablePrintInputEx(PortTable* p, rim_print_f print_index_map)
{
    SF_LNODE* pos;

    for ( PortObject* po = (PortObject*)sflist_first(p->pt_polist, &pos);
        po != nullptr;
        po = (PortObject*)sflist_next(&pos) )
    {
        PortObjectPrintEx(po, print_index_map);
    }
}

int PortTablePrintCompiledEx(PortTable* p, rim_print_f print_index_map)
{
    LogMessage(" *** PortTableCompiled  [ %d compiled port groups ] \n\n",
        p->pt_mpo_hash->count);

    for ( SFGHASH_NODE* node = sfghash_findfirst(p->pt_mpo_hash);
        node!= 0;
        node = sfghash_findnext(p->pt_mpo_hash) )
    {
        PortObject2* po = (PortObject2*)node->data;
        PortObject2PrintEx(po, print_index_map);
    }

    return 0;
}

void PortTablePrintInput(PortTable* p)
{
    LogMessage("*** %d PortObjects in Table\n", p->pt_polist->count);
    SF_LNODE* pos;

    for ( PortObject* po = (PortObject*)sflist_first(p->pt_polist, &pos);
        po!=0;
        po = (PortObject*)sflist_next(&pos) )
    {
        PortObjectPrint(po);
    }
}

/*
   Prints the original (normalized) PortGroups and
   as specified by the user
*/
void PortTablePrintUserRules(PortTable* p)
{
    /* normalized user PortObjects and rule ids */
    LogMessage(">>>PortTable - Rules\n");
    SF_LNODE* cursor;

    for ( PortObject* po = (PortObject*)sflist_first(p->pt_polist, &cursor);
        po!= 0;
        po = (PortObject*)sflist_next(&cursor) )
    {
        PortObjectPrint(po);
    }
    /* port array of rule ids */
}

/*
    Prints the Unique Port Groups and rules that reference them
*/
void PortTablePrintPortGroups(PortTable* p)
{
    /* normalized user PortObjects and rule ids */
    LogMessage(">>>PortTable - Compiled Port Groups\n");
    LogMessage("   [ %d port groups ] \n\n", p->pt_mpo_hash->count);

    for ( SFGHASH_NODE* ponode = sfghash_findfirst(p->pt_mpo_hash);
        ponode!= 0;
        ponode = sfghash_findnext(p->pt_mpo_hash) )
    {
        PortObject2* po = (PortObject2*)ponode->data;
        PortObject2Print(po);
    }
    /* port array of rule ids */
}

void RuleListSortUniq(SF_LIST* rl)
{
    int lastRuleIndex = -1;
    SF_LNODE* pos = nullptr;
    unsigned uniqElements = 0;

    int* rlist = RuleListToSortedArray(rl);

    if (!rlist )
        return;

    int* currNode = (int*)sflist_first(rl, &pos);

    if ( !currNode )
        return;

    for ( unsigned i = 0; i < rl->count; i++ )
    {
        if (rlist[i] > lastRuleIndex)
        {
            *currNode = lastRuleIndex = rlist[i];
            //replace the next element in place
            currNode = (int*)sflist_next(&pos);
            uniqElements++;
        }
    }

    //free the remaining list nodes
    while (uniqElements != rl->count)
    {
        int* node = (int*)sflist_remove_tail(rl);
        snort_free(node);
    }

    snort_free(rlist);
}

/**Sort and make rule index in all port objects unique. Multiple policies may add
 * the same rule which can lead to duplication.
 */
void PortTableSortUniqRules(PortTable* p)
{
    SF_LNODE* pos = nullptr;

    for ( PortObject* po = (PortObject*)sflist_first(p->pt_polist, &pos);
        po != nullptr;
        po = (PortObject*)sflist_next(&pos) )
    {
        RuleListSortUniq(po->rule_list);
    }
}

