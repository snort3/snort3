//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/* sfxhash.c
 *
 *  A Customized hash table library for storing and accessing key + data pairs.
 *
 *  This table incorporates a memory manager (memcap.c) to provide a memory cap,
 *  and an automatic node recovery system for out of memory management. Keys and
 *  Data are copied into the hash table during the add operation. The data may
 *  be allocated and free'd by the user (by setting the datasize to zero ). A
 *  user callback is provided to allow the user to do cleanup whenever a node
 *  is released, by either the ANR system or the relase() function.
 *
 *  Users can and should delete nodes when they know they are not needed anymore,
 *  but this custom table is designed for the case where nodes are allocated
 *  permanently, we have to limit memory, and we wish to recycle old nodes.
 *  Many problems have a natural node ageing paradigm working in our favor,
 *  so automated node aging makes sense. i.e. thresholding, tcp state.
 *
 *  This hash table maps keys to data.  All keys must be unique.
 *  Uniqueness is enforcedby the code.
 *
 *  Features:
 *
 *    1) Keys must be fixed length (per table) binary byte sequences.
 *         keys are copied during the add function
 *    2) Data must be fixed length (per table) binary byte sequences.
 *         data is copied during the add function - if datasize > 0
 *       Data may be managed by the user as well.
 *    3) Table row sizes can be automatically adjusted to
 *       the nearest prime number size during table initialization/creation.
 *    4) Memory management includes tracking the size of each allocation,
 *       number of allocations, enforcing a memory cap, and automatic node
 *       recovery - when  memory is low the oldest untouched node
 *       is unlinked and recycled for use as a new node.
 *
 *  Per Node Memory Usage:
 *  ----------------------
 *     SFXHASH_NODE bytes
 *     KEYSIZE bytes
 *     [DATASIZE bytes] if datasize > 0 during call to sfxhash_new.
 *
 *  The hash node memory (sfxhash_node,key,and data) is allocated with
 *  one call to s_alloc/memcap_alloc.
 *
 *  Author: Marc Norton
 *
 *  2003-06-03: cmg - added sfxhash_{l,m}ru to return {least,most}
 *              recently used node from the global list
 *
 *              - added _anrcount function
 *              - changed count function to return unsigned to match structure
 *
 *  2003-06-11: cmg added
 *              overhead_bytes + blocks to separate out the
 *              memcap constraints from the hash table itself
 *              find success v fail
 *
 *  2003-06-19: cmg added
 *
 *              ability to set own hash function
 *              ability to set own key cmp function
 *
 *  2003-06-30: rdempster
 *              fixed bug in that would anr from the freelist
 *
 *  2005-11-15: modified sfxhash_add to check if 'data' is zero before memcpy'ing.
 *              this allows user to pass null for data, and set up the data area
 *              themselves after the call - this is much more flexible.
 *  8/31/2006: man - changed to use prime table lookup.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#include "sfxhash.h"
#include "sfprimetable.h"
#include "sfhashfcn.h"

/*
 * Implements SFXHASH as specialized hash container
 */

/*
* Private Malloc - abstract the memory system
*/
static inline void* s_alloc(SFXHASH* t, int n)
{
    return sfmemcap_alloc(&t->mc, n);
}

static inline void s_free(SFXHASH* t, void* p)
{
    sfmemcap_free(&t->mc, p);
}

/*
 *   User access to the memory management, do they need it ? WaitAndSee
 */
void* sfxhash_alloc(SFXHASH* t, unsigned nbytes)
{
    return s_alloc(t, nbytes);
}

void sfxhash_free(SFXHASH* t, void* p)
{
    s_free(t, p);
}

static int sfxhash_nearest_powerof2(int nrows)
{
    unsigned i;

    nrows -= 1;
    for (i=1; i<sizeof(nrows) * 8; i <<= 1)
        nrows = nrows | (nrows >> i);
    nrows += 1;

    return nrows;
}

int sfxhash_calcrows(int num)
{
    return sfxhash_nearest_powerof2(num);
//  return sf_nearest_prime( nrows );
}

/*
 * Create a new hash table
 *
 * By default, this will "splay" nodes to the top of a free list.
 *
 * nrows    number of rows in hash table
 * keysize  key size in bytes, same for all keys
 * datasize datasize in bytes, zero indicates user manages data
 * maxmem   maximum memory to use in bytes
 * anr_flag Automatic Node Recovery boolean flag
 * anrfree  users Automatic Node Recovery memory release function
 * usrfree  users standard memory release function
 *
 * return SFXHASH*
 * retval  0 out of memory
 * retval !0 Valid SFXHASH pointer
 */
/*
  Notes:
  if nrows < 0 don't cal the nearest powerof2.
  datasize must be the same for all entries, unless datasize is zero.
  maxmem of 0 indicates no memory limits.

*/
SFXHASH* sfxhash_new(int nrows, int keysize, int datasize, unsigned long maxmem,
    int anr_flag,
    SFXHASH_FREE_FCN anrfree,
    SFXHASH_FREE_FCN usrfree,
    int recycle_flag)
{
    int i;
    SFXHASH* h;

    if ( nrows > 0 ) /* make sure we have a prime number */
    {
        /* If nrows is not a power of two, need to find the
         * next highest power of two */
        nrows = sfxhash_nearest_powerof2(nrows);
    }
    else   /* use the magnitude of nrows as is */
    {
        nrows = -nrows;
    }

    /* Allocate the table structure from general memory */
    h = (SFXHASH*)snort_calloc(sizeof(SFXHASH));

    /* this has a default hashing function */
    h->sfhashfcn = sfhashfcn_new(nrows);
    sfmemcap_init(&h->mc, maxmem);

    /* Allocate the array of node ptrs */
    h->table = (SFXHASH_NODE**)s_alloc(h, sizeof(SFXHASH_NODE*) * nrows);

    if ( !h->table )
    {
        snort_free(h->sfhashfcn);
        snort_free(h);
        return 0;
    }

    for ( i=0; i<nrows; i++ )
    {
        h->table[i] = 0;
    }

    h->anrfree  = anrfree;
    h->usrfree  = usrfree;
    h->keysize  = keysize;

#ifdef WORDS_MUSTALIGN
    if ((h->keysize) & 7)
        h->pad = (8 - ((h->keysize) & 7));
#else
    h->pad = 0;
#endif
    h->datasize = datasize;
    h->nrows    = nrows;
    h->max_nodes = 0;
    h->crow     = 0;
    h->cnode    = 0;
    h->count    = 0;
    h->ghead    = 0;
    h->gtail    = 0;
    h->anr_count= 0;
    h->anr_tries= 0;
    h->anr_flag = anr_flag;
    h->splay    = 1;
    h->recycle_nodes = recycle_flag;

    h->find_success = 0;
    h->find_fail    = 0;

    /* save off how much we've already allocated from our memcap */
    h->overhead_bytes = h->mc.memused;
    h->overhead_blocks = h->mc.nblocks;

    return h;
}

/*
 *  Set the maximum nodes used in this hash table.
 *  Specifying 0 is unlimited (or otherwise limited by memcap).
 *
 * h SFXHASH table pointer
 * max_nodes maximum nodes to allow.
 *
 */
void sfxhash_set_max_nodes(SFXHASH* h, int max_nodes)
{
    if (h)
    {
        h->max_nodes = max_nodes;
    }
}

/*!
 *  Set Splay mode : Splays nodes to front of list on each access
 *
 * t SFXHASH table pointer
 * n boolean flag toggles splaying of hash nodes
 *
 */
void sfxhash_splaymode(SFXHASH* t, int n)
{
    t->splay = n;
}

/*!
 *  Free all nodes in the free list
 *
 *  Removes and frees all of the nodes in the free list
 *  No need to call the user free, since that should've been
 *  done when those nodes were put back in the free list.
 *
 * h SFXHASH table pointer
 */
static void sfxhash_delete_free_list(SFXHASH* t)
{
    SFXHASH_NODE* cur = NULL;
    SFXHASH_NODE* next = NULL;

    if (t == NULL || t->fhead == NULL)
        return;

    cur = t->fhead;

    while (cur != NULL)
    {
        next = cur->gnext;
        s_free(t, (void*)cur);
        cur = next;
    }

    t->fhead = NULL;
    t->ftail = NULL;
}

/*!
 *  Delete the hash Table
 *
 *  free key's, free node's, and free the users data.
 *
 * h SFXHASH table pointer
 *
 */
void sfxhash_delete(SFXHASH* h)
{
    unsigned i;
    SFXHASH_NODE* node, * onode;

    if ( !h )
        return;

    if ( h->sfhashfcn )
        sfhashfcn_free(h->sfhashfcn);

    if ( h->table )
    {
        for (i=0; i<h->nrows; i++)
        {
            for ( node=h->table[i]; node; )
            {
                onode = node;
                node  = node->next;

                /* Notify user that we are about to free this node function */
                if ( h->usrfree )
                    h->usrfree(onode->key, onode->data);

                s_free(h,onode);
            }
        }
        s_free(h, h->table);
        h->table = 0;
    }

    sfxhash_delete_free_list(h);

    snort_free(h);   /* free the table from general memory */
}

/*!
 *  Empty out the hash table
 *
 * h SFXHASH table pointer
 *
 * return -1 on error
 */
int sfxhash_make_empty(SFXHASH* h)
{
    SFXHASH_NODE* n = NULL;
    SFXHASH_NODE* tmp = NULL;
    unsigned i;

    if (h == NULL)
        return -1;

    for (i = 0; i < h->nrows; i++)
    {
        for (n = h->table[i]; n != NULL; n = tmp)
        {
            tmp = n->next;
            if (sfxhash_free_node(h, n) != SFXHASH_OK)
            {
                return -1;
            }
        }
    }

    h->max_nodes = 0;
    h->crow = 0;
    h->cnode = NULL;
    h->count = 0;
    h->ghead = NULL;
    h->gtail = NULL;
    h->anr_count = 0;
    h->anr_tries = 0;
    h->find_success = 0;
    h->find_fail = 0;

    return 0;
}

/** Save the freed node for later use (recylcing).
 *  Free List - uses the NODE gnext/gprev fields
 */
static void sfxhash_save_free_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    /* Add A Node to the Free Node List */
    if ( t->fhead ) /* add the node to head of the the existing list */
    {
        hnode->gprev    = 0;
        hnode->gnext    = t->fhead;
        t->fhead->gprev = hnode;
        t->fhead        = hnode;
        /* tail is not affected */
    }
    else /* 1st node in this list */
    {
        hnode->gprev = 0;
        hnode->gnext = 0;
        t->fhead    = hnode;
        t->ftail    = hnode;
    }
}

/**Get a previously freed node for reuse.
 */
static SFXHASH_NODE* sfxhash_get_free_node(SFXHASH* t)
{
    SFXHASH_NODE* node = t->fhead;

    /* Remove A Node from the Free Node List - remove the head node */
    if ( t->fhead  )
    {
        t->fhead = t->fhead->gnext;
        if ( t->fhead )
            t->fhead->gprev = 0;

        if ( t->ftail  == node ) /* no more nodes - clear the tail */
            t->ftail  =  0;
    }

    return node;
}

static void sfxhash_glink_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    /* Add The Node */
    if ( t->ghead ) /* add the node to head of the the existing list */
    {
        hnode->gprev    = 0;
        hnode->gnext    = t->ghead;
        t->ghead->gprev = hnode;
        t->ghead        = hnode;
        /* tail is not affected */
    }
    else /* 1st node in this list */
    {
        hnode->gprev = 0;
        hnode->gnext = 0;
        t->ghead    = hnode;
        t->gtail    = hnode;
    }
}

static void sfxhash_gunlink_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    if ( t->gnode == hnode ) /* if this was the global next node */
    {
        t->gnode = hnode->gnext;
    }

    /* Remove the Head Node */
    if ( t->ghead == hnode ) /* add the node to head of the the existing list */
    {
        t->ghead = t->ghead->gnext;
        if ( t->ghead )
            t->ghead->gprev = 0;
    }

    if ( hnode->gprev )
        hnode->gprev->gnext = hnode->gnext;
    if ( hnode->gnext )
        hnode->gnext->gprev = hnode->gprev;

    if ( t->gtail  == hnode )
        t->gtail  =  hnode->gprev;
}

/**Move node to the front of global list. Node movement is application specific.
 */
void sfxhash_gmovetofront(SFXHASH* t, SFXHASH_NODE* hnode)
{
    if ( hnode != t->ghead )
    {
        sfxhash_gunlink_node(t, hnode);
        sfxhash_glink_node(t, hnode);
    }
}

/*
 *
 */
static void sfxhash_link_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    /* Add The Node to the Hash Table Row List */
    if ( t->table[hnode->rindex] ) /* add the node to the existing list */
    {
        hnode->prev = 0;  // insert node as head node
        hnode->next=t->table[hnode->rindex];
        t->table[hnode->rindex]->prev = hnode;
        t->table[hnode->rindex] = hnode;
    }
    else /* 1st node in this list */
    {
        hnode->prev=0;
        hnode->next=0;
        t->table[hnode->rindex] = hnode;
    }
}

static void sfxhash_unlink_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    if ( hnode->prev )  // definitely not the 1st node in the list
    {
        hnode->prev->next = hnode->next;
        if ( hnode->next )
            hnode->next->prev = hnode->prev;
    }
    else if ( t->table[hnode->rindex] )  // must be the 1st node in the list
    {
        t->table[hnode->rindex] = t->table[hnode->rindex]->next;
        if ( t->table[hnode->rindex] )
            t->table[hnode->rindex]->prev = 0;
    }
}

/*
 *  move a node to the front of the row list at row = 'index'
 */
static void movetofront(SFXHASH* t, SFXHASH_NODE* n)
{
    /* Modify Hash Node Row List */
    if ( t->table[n->rindex] != n ) // if not at front of list already...
    {
        /* Unlink the node */
        sfxhash_unlink_node(t, n);

        /* Link at front of list */
        sfxhash_link_node(t, n);
    }

    /* Move node in the global hash node list to the front */
    if (n == t->gnode)
        t->gnode = n->gnext;
    sfxhash_gmovetofront(t, n);
}

/*
 * Allocat a new hash node, uses Auto Node Recovery if needed and enabled.
 *
 * The oldest node is the one with the longest time since it was last touched,
 * and does not have any direct indication of how long the node has been around.
 * We don't monitor the actual time since last being touched, instead we use a
 * splayed global list of node pointers. As nodes are accessed they are splayed
 * to the front of the list. The oldest node is just the tail node.
 *
 */
static SFXHASH_NODE* sfxhash_newnode(SFXHASH* t)
{
    SFXHASH_NODE* hnode;

    /* Recycle Old Nodes - if any */
    hnode = sfxhash_get_free_node(t);

    /* Allocate memory for a node */
    if ( !hnode )
    {
        if ((t->max_nodes == 0) || (t->count < t->max_nodes))
        {
            hnode = (SFXHASH_NODE*)s_alloc(t, sizeof(SFXHASH_NODE) + t->pad +
                t->keysize + t->datasize);
        }
    }

    /*  If we still haven't found hnode, we're at our memory limit.
     *
     *  Uses Automatic Node Recovery, to recycle the oldest node-based on access
     *  (Unlink and reuse the tail node)
     */
    if ( !hnode && t->anr_flag && t->gtail )
    {
        /* Find the oldes node the users willing to let go. */
        for (hnode = t->gtail; hnode; hnode = hnode->gprev )
        {
            if ( t->anrfree ) /* User has provided a permission+release callback function */
            {
                t->anr_tries++; /* Count # ANR requests */

                /* Ask the user for permission to release this node, but let them say no! */
                if ( t->anrfree(hnode->key, hnode->data) )
                {
                    /* NO, don't recycle this node, user's not ready to let it go. */
                    continue;
                }

                /* YES, user said we can recycle this node */
            }

            sfxhash_gunlink_node(t, hnode);   /* unlink from the global list */
            sfxhash_unlink_node(t, hnode);   /* unlink from the row list */
            t->count--;
            t->anr_count++; /* count # of ANR operations */
            break;
        }
    }

    /* either we are returning a node or we're all full and the user
     * won't let us allocate anymore and we return NULL */
    return hnode;
}

/*
 *
 *  Find a Node based on the key, return the node and the index.
 *  The index is valid even if the return value is NULL, in which
 *  case the index is the corect row in which the node should be
 *  created.
 *
 */

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

static SFXHASH_NODE* sfxhash_find_node_row(SFXHASH* t, const void* key, int* rindex)
{
    unsigned hashkey;
    int index;
    SFXHASH_NODE* hnode;

    hashkey = t->sfhashfcn->hash_fcn(t->sfhashfcn,
        (unsigned char*)key,
        t->keysize);

/*     printf("hashkey: %u t->keysize: %d\n", hashkey, t->keysize);
       flowkey_fprint(stdout, key);
       printf("****\n"); */

//     index   = hashkey % t->nrows;
    /* Modulus is slow. Switched to a table size that is a power of 2. */
    index  = hashkey & (t->nrows - 1);

    *rindex = index;

    for ( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if ( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
        {
            if ( t->splay > 0 )
                movetofront(t,hnode);

            t->find_success++;
            return hnode;
        }
    }

    t->find_fail++;
    return NULL;
}

/*!
 * Add a key + data pair to the hash table
 *
 * 2003-06-06:
 *  - unique_tracker.c assumes that this splays
 *    nodes to the top when they are added.
 *
 *    This is done because of the successful find.
 *
 * t SFXHASH table pointer
 * key  users key pointer
 * data  users data pointer
 *
 * eturn integer
 * retval SFXHASH_OK      success
 * retval SFXHASH_INTABLE already in the table, t->cnode points to the node
 * retval SFXHASH_NOMEM   not enough memory
 */
static int sfxhash_add_ex(SFXHASH* t, const void* key, void* data, void** data_ptr)
{
    int index;
    SFXHASH_NODE* hnode;

    /* Enforce uniqueness: Check for the key in the table */
    hnode = sfxhash_find_node_row(t, key, &index);

    if ( hnode )
    {
        t->cnode = hnode;
        if (data_ptr)
            *data_ptr = hnode->data;
        return SFXHASH_INTABLE; /* found it - return it. */
    }

    /*
     *  Alloc new hash node - allocate key space and data space at the same time.
     */
    hnode = sfxhash_newnode(t);
    if ( !hnode )
    {
        return SFXHASH_NOMEM;
    }

    /* Set up the new key pointer */
    hnode->key = (char*)hnode + sizeof(SFXHASH_NODE);

    /* Copy the key */
    memcpy(hnode->key,key,t->keysize);

    /* Save our table row index */
    hnode->rindex = index;

    /* Copy the users data - or if datasize is zero set ptr to users data */
    if ( t->datasize )
    {
        /* Set up the new data pointer */
        hnode->data= (char*)hnode + sizeof(SFXHASH_NODE) + t->pad + t->keysize;

        if (data)
        {
            memcpy(hnode->data,data,t->datasize);
        }
        if (data_ptr)
            *data_ptr = hnode->data;
    }
    else
    {
        hnode->data = data;
    }

    /* Link the node into the table row list */
    sfxhash_link_node (t, hnode);

    /* Link at the front of the global node list */
    sfxhash_glink_node(t, hnode);

    /* Track # active nodes */
    t->count++;

    return SFXHASH_OK;
}

int sfxhash_add(SFXHASH* t, void* key, void* data)
{
    return sfxhash_add_ex(t, key, data, NULL);
}

/*!
 * Add a key to the hash table, return the hash node
 *
 * 2003-06-06:
 *  - unique_tracker.c assumes that this splays
 *    nodes to the top when they are added.
 *
 *    This is done because of the successful find.
 *
 * t SFXHASH table pointer
 * key  users key pointer
 *
 * return integer
 * retval SFXHASH_OK      success
 * retval SFXHASH_INTABLE already in the table, t->cnode points to the node
 * retval SFXHASH_NOMEM   not enough memory
 */
SFXHASH_NODE* sfxhash_get_node(SFXHASH* t, const void* key)
{
    int index;
    SFXHASH_NODE* hnode;

    /* Enforce uniqueness: Check for the key in the table */
    hnode = sfxhash_find_node_row(t, key, &index);

    if ( hnode )
    {
        t->cnode = hnode;

        return hnode; /* found it - return it. */
    }

    /*
     *  Alloc new hash node - allocate key space and data space at the same time.
     */
    hnode = sfxhash_newnode(t);
    if ( !hnode )
    {
        return NULL;
    }

    /* Set up the new key pointer */
    hnode->key = (char*)hnode + sizeof(SFXHASH_NODE);

    /* Copy the key */
    memcpy(hnode->key,key,t->keysize);

    /* Save our table row index */
    hnode->rindex = index;

    /* Copy the users data - or if datasize is zero set ptr to users data */
    if ( t->datasize )
    {
        /* Set up the new data pointer */
        hnode->data = (char*)hnode + sizeof(SFXHASH_NODE) + t->pad + t->keysize;
    }
    else
    {
        hnode->data = NULL;
    }

    /* Link the node into the table row list */
    sfxhash_link_node (t, hnode);

    /* Link at the front of the global node list */
    sfxhash_glink_node(t, hnode);

    /* Track # active nodes */
    t->count++;

    return hnode;
}

/*!
 * Find a Node based on the key
 *
 * t SFXHASH table pointer
 * key  users key pointer
 *
 * return SFXHASH_NODE*   valid pointer to the hash node
 * retval 0               node not found
 *
 */
SFXHASH_NODE* sfxhash_find_node(SFXHASH* t, const void* key)
{
    int rindex;

    return sfxhash_find_node_row(t, key, &rindex);
}

/*!
 * Find the users data based associated with the key
 *
 * t SFXHASH table pointer
 * key  users key pointer
 *
 * return void*   valid pointer to the users data
 * retval 0       node not found
 *
 */
void* sfxhash_find(SFXHASH* t, void* key)
{
    SFXHASH_NODE* hnode;
    int rindex;

    hnode = sfxhash_find_node_row(t, key, &rindex);

    if ( hnode )
        return hnode->data;

    return NULL;
}

/**
 * Get the HEAD of the in use list
 *
 * t table pointer
 *
 * return the head of the list or NULL
 */
SFXHASH_NODE* sfxhash_ghead(SFXHASH* t)
{
    if (t)
    {
        return t->ghead;
    }

    return NULL;
}

/**
 * Walk the global list
 *
 * n current node
 *
 * return the next node in the list or NULL when at the end
 */
SFXHASH_NODE* sfxhash_gnext(SFXHASH_NODE* n)
{
    if (n)
    {
        return n->gnext;
    }

    return NULL;
}

/**
 * Walk the global list
 *
 * n current node
 *
 * return the next node in the list or NULL when at the end
 */
SFXHASH_NODE* sfxhash_gfindnext(SFXHASH* t)
{
    SFXHASH_NODE* n;

    n = t->gnode;
    if (n)
        t->gnode = n->gnext;
    return n;
}

/**
 * Get the HEAD of the in use list
 *
 * t table pointer
 *
 * return the head of the list or NULL
 */
SFXHASH_NODE* sfxhash_gfindfirst(SFXHASH* t)
{
    if (t)
    {
        if (t->ghead)
            t->gnode = t->ghead->gnext;
        else
            t->gnode = NULL;
        return t->ghead;
    }
    return NULL;
}

/*!
 * Return the most recently used data from the global list
 *
 * t SFXHASH table pointer
 *
 * return void*   valid pointer to the users data
 * retval 0       node not found
 *
 */
void* sfxhash_mru(SFXHASH* t)
{
    SFXHASH_NODE* hnode;

    hnode = sfxhash_ghead(t);

    if ( hnode )
        return hnode->data;

    return NULL;
}

/*!
 * Return the least recently used data from the global list
 *
 * t SFXHASH table pointer
 *
 * return void*   valid pointer to the users data
 * retval 0       node not found
 *
 */
void* sfxhash_lru(SFXHASH* t)
{
    SFXHASH_NODE* hnode;

    hnode = t->gtail;

    if ( hnode )
        return hnode->data;

    return NULL;
}

/*!
 * Return the most recently used node from the global list
 *
 * t SFXHASH table pointer
 *
 * return SFXHASH_NODE*   valid pointer to a node
 * retval 0       node not found
 *
 */
SFXHASH_NODE* sfxhash_mru_node(SFXHASH* t)
{
    SFXHASH_NODE* hnode;

    hnode = sfxhash_ghead(t);

    if ( hnode )
        return hnode;

    return NULL;
}

/*!
 * Return the least recently used node from the global list
 *
 * t SFXHASH table pointer
 *
 * return SFXHASH_NODE*   valid pointer to a node
 * retval 0       node not found
 *
 */
SFXHASH_NODE* sfxhash_lru_node(SFXHASH* t)
{
    SFXHASH_NODE* hnode;

    hnode = t->gtail;

    if ( hnode )
        return hnode;

    return NULL;
}

/*!
 * Get some hash table statistics. NOT FOR REAL TIME USE.
 *
 *
 * t SFXHASH table pointer
 * param filled how many
 *
 * return max depth of the table
 *
 */
unsigned sfxhash_maxdepth(SFXHASH* t)
{
    unsigned i;
    unsigned max_depth = 0;

    SFXHASH_NODE* hnode;

    for ( i=0; i<t->nrows; i++ )
    {
        unsigned cur_depth = 0;

        for (hnode = t->table[i]; hnode != NULL; hnode = hnode->next)
        {
            cur_depth++;
        }

        if (cur_depth > max_depth)
            max_depth = cur_depth;
    }

    return max_depth;
}

/*
 *  Unlink and free the node
 */
int sfxhash_free_node(SFXHASH* t, SFXHASH_NODE* hnode)
{
    sfxhash_unlink_node(t, hnode);   /* unlink from the hash table row list */

    sfxhash_gunlink_node(t, hnode);   /* unlink from global-hash-node list */

    t->count--;

    if ( t->usrfree )
    {
        t->usrfree(hnode->key, hnode->data);
    }

    if ( t->recycle_nodes )
    {
        sfxhash_save_free_node(t, hnode);
    }
    else
    {
        s_free(t, hnode);
    }

    return SFXHASH_OK;
}

/*!
 * Remove a Key + Data Pair from the table.
 *
 * t SFXHASH table pointer
 * key  users key pointer
 *
 * return 0   success
 * retval !0  failed
 *
 */
int sfxhash_remove(SFXHASH* t, void* key)
{
    SFXHASH_NODE* hnode;
    unsigned hashkey, index;

    hashkey = t->sfhashfcn->hash_fcn(t->sfhashfcn,
        (unsigned char*)key,
        t->keysize);

//    index = hashkey % t->nrows;
    /* Modulus is slow */
    index   = hashkey & (t->nrows - 1);

    for ( hnode=t->table[index]; hnode; hnode=hnode->next )
    {
        if ( !t->sfhashfcn->keycmp_fcn(hnode->key,key,t->keysize) )
        {
            return sfxhash_free_node(t, hnode);
        }
    }

    return SFXHASH_ERR;
}

/*
   Internal use only
*/
static void sfxhash_next(SFXHASH* t)
{
    if ( !t->cnode )
        return;

    /* Next node in current node list */
    t->cnode = t->cnode->next;
    if ( t->cnode )
    {
        return;
    }

    /* Next row
       Get 1st node in next non-emtoy row/node list */
    for ( t->crow++; t->crow < t->nrows; t->crow++ )
    {
        t->cnode = t->table[ t->crow ];
        if ( t->cnode )
        {
            return;
        }
    }
}

/*!
 * Find and return the first hash table node
 *
 * t SFXHASH table pointer
 *
 * return 0   failed
 * retval !0  valid SFXHASH_NODE *
 *
 */
SFXHASH_NODE* sfxhash_findfirst(SFXHASH* t)
{
    SFXHASH_NODE* n;

    if (!t)
        return NULL;

    /* Start with 1st row */
    for ( t->crow=0; t->crow < t->nrows; t->crow++ )
    {
        /* Get 1st Non-Null node in row list */
        t->cnode = t->table[ t->crow ];
        if ( t->cnode )
        {
            n = t->cnode;
            sfxhash_next(t);   // load t->cnode with the next entry
            return n;
        }
    }

    return NULL;
}

/*!
 * Find and return the next hash table node
 *
 * t SFXHASH table pointer
 *
 * return 0   failed
 * retval !0  valid SFXHASH_NODE *
 *
 */
SFXHASH_NODE* sfxhash_findnext(SFXHASH* t)
{
    SFXHASH_NODE* n;

    n = t->cnode;
    if ( !n ) /* Done, no more entries */
    {
        return NULL;
    }

    /*
      Preload next node into current node
    */
    sfxhash_next(t);

    return n;
}

/**
 * Make sfhashfcn use a separate set of opcodes for the backend.
 *
 * h sfhashfcn ptr
 * hash_fcn user specified hash function
 * keycmp_fcn user specified key comparison function
 */

int sfxhash_set_keyops(SFXHASH* h,
    unsigned (* hash_fcn)(SFHASHFCN* p, unsigned char* d, int n),
    int (* keycmp_fcn)(const void* s1, const void* s2, size_t n))
{
    if (h && hash_fcn && keycmp_fcn)
    {
        return sfhashfcn_set_keyops(h->sfhashfcn, hash_fcn, keycmp_fcn);
    }

    return -1;
}

int sfxhash_add_return_data_ptr(SFXHASH* t, const void* key, void** data)
{
    if ( !t->datasize )
        return SFXHASH_ERR;

    *data = NULL;

    return sfxhash_add_ex(t, key, NULL, data);
}

/*
 * -----------------------------------------------------------------------------------------
 *   Test Driver for Hashing
 * -----------------------------------------------------------------------------------------
 */
#ifdef SFXHASH_MAIN

/*
   This is called when the user releases a node or kills the table
*/
int usrfree(void* key, void* data)
{
    /* Release any data you need to */
    return 0;
}

/*
   Auto Node Recovery Callback - optional

   This is called to ask the user to kill a node, if it reutrns !0 than the hash
   library does not kill this node.  If the user os willing to let the node die,
   the user must do any free'ing or clean up on the node during this call.
*/
int anrfree(void* key, void* data)
{
    static int bx = 0;  // test only

    /* Decide if we can free this node. */

    //bx++; if(bx == 4 )bx=0;       /* for testing */

    /* if we are allowing the node to die, kill it */
    if ( !bx )
        usrfree(key, data);

    return bx;  /* Allow the caller to  kill this nodes data + key */
}

/*
 *       Hash test program : use 'sfxhash 1000 50000' to stress the Auto_NodeRecover feature
 */
int main(int argc, char** argv)
{
    int i;
    SFXHASH* t;
    SFXHASH_NODE* n;
    char strkey[256], strdata[256], * p;
    int num = 100;
    int mem = 0;

    memset(strkey,0,20);
    memset(strdata,0,20);

    if ( argc > 1 )
    {
        num = atoi(argv[1]);
    }

    if ( argc > 2 )
    {
        mem = atoi(argv[2]);
    }

    /* Create a Hash Table */
    t = sfxhash_new(100,         /* one row per element in table, when possible */
        20,                     /* key size :  padded with zeros */
        20,                     /* data size:  padded with zeros */
        mem,                    /* max bytes,  0=no max */
        1,                      /* enable AutoNodeRecovery */
        anrfree,                /* provide a function to let user know we want to kill a node */
        usrfree,              /* provide a function to release user memory */
        1);                   /* Recycle nodes */
    if (!t)
    {
        printf("Low Memory\n");
        exit(0);
    }
    /* Add Nodes to the Hash Table */
    for (i=0; i<num; i++)
    {
        snprintf(strkey, sizeof(strkey), "KeyWord%5.5d",i+1);
        strkey[sizeof(strkey) - 1] = '\0';
        snprintf(strdata, sizeof(strdata), "KeyWord%5.5d",i+1);
        strdata[sizeof(strdata) - 1] = '\0';
        //strupr(strdata);
        sfxhash_add(t, strkey /* user key */,  strdata /* user data */);
    }

    /* Find and Display Nodes in the Hash Table */
    printf("\n** FIND KEY TEST\n");
    for (i=0; i<num; i++)
    {
        snprintf(strkey, sizeof(strkey) - 1, "KeyWord%5.5d",i+1);
        strkey[sizeof(strkey) - 1] = '\0';

        p = (char*)sfxhash_find(t, strkey);

        if (p)
            printf("Hash-key=%*s, data=%*s\n", strlen(strkey),strkey, strlen(strkey), p);
    }

    /* Show memcap memory */
    printf("\n...******\n");
    sfmemcap_showmem(&t->mc);
    printf("...******\n");

    /* Display All Nodes in the Hash Table findfirst/findnext */
    printf("\n...FINDFIRST / FINDNEXT TEST\n");
    for ( n  = sfxhash_findfirst(t);
        n != 0;
        n  = sfxhash_findnext(t) )
    {
        printf("hash-findfirst/next: n=%x, key=%s, data=%s\n", n, n->key, n->data);

        /*
          remove node we are looking at, this is first/next safe.
        */
        if ( sfxhash_remove(t,n->key) )
        {
            printf("...ERROR: Could not remove the key node\n");
        }
        else
        {
            printf("...key node removed\n");
        }
    }

    printf("...Auto-Node-Recovery: %d recycle attempts, %d completions.\n",t->anr_tries,
        t->anr_count);

    /* Free the table and it's user data */
    printf("...sfxhash_delete\n");

    sfxhash_delete(t);

    printf("\nnormal pgm finish\n\n");

    return 0;
}

#endif

