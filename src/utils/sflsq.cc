//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

/*
*   sflsq.c
*
*   Simple list, stack, queue, and dictionary implementations
*   ( most of these implementations are list based - not performance monsters,
*     and they all use alloc via s_alloc/s_free )
*   Stack based Ineteger and Pointer Stacks, these are for performance.(inline would be better)
*
*   11/05/2005 - man - Added sflist_firstx() and sflist_nextx() with user
*   provided SF_NODE inputs for tracking the list position.  This allows
*   multiple readers to traverse a list.
*/

#include "sflsq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/snort_types.h"

/*
*  private alloc
*/
static void* s_alloc(size_t n)
{
    void* p = (void*)calloc(1,n);
    return p;
}

/*
*  private free
*/
static void s_free(void* p)
{
    if ( p )
        free(p);
}

/*
*   INIT - called by the NEW functions
*/
void sflist_init(SF_LIST* s)
{
    s->count=0;
    s->head = s->tail = 0;
}

/*
*    NEW
*/
SF_LIST* sflist_new(void)
{
    SF_LIST* s;
    s = (SF_LIST*)s_alloc(sizeof(SF_LIST) );
    if ( s )
        sflist_init(s);
    return s;
}

SF_STACK* sfstack_new(void)
{
    return (SF_STACK*)sflist_new();
}

SF_QUEUE* sfqueue_new(void)
{
    return (SF_QUEUE*)sflist_new();
}

/*
*  Add-before Item
*/
int sflist_add_before(SF_LIST* s, SF_LNODE* lnode, NODE_DATA ndata)
{
    SF_LNODE* q;

    if ( !lnode )
        return 0;

    /* Add to head of list */
    if ( s->head == lnode )
    {
        return sflist_add_head (s, ndata);
    }
    else
    {
        q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE) );
        if ( !q )
        {
            return -1;
        }
        q->ndata = (NODE_DATA)ndata;

        q->next = lnode;
        q->prev = lnode->prev;
        lnode->prev->next = q;
        lnode->prev       = q;
    }
    s->count++;

    return 0;
}

/*
*     ADD to List/Stack/Queue/Dictionary
*/
/*
*  Add-Head Item
*/
int sflist_add_head(SF_LIST* s, NODE_DATA ndata)
{
    SF_LNODE* q;
    if (!s->head)
    {
        q = s->tail = s->head = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        if (!q)
            return -1;
        q->ndata = (NODE_DATA)ndata;
        q->next = 0;
        q->prev = 0;
    }
    else
    {
        q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        if (!q)
            return -1;
        q->ndata = ndata;
        q->next = s->head;
        q->prev = 0;
        s->head->prev = q;
        s->head = q;
    }
    s->count++;

    return 0;
}

/*
*  Add-Tail Item
*/
int sflist_add_tail(SF_LIST* s, NODE_DATA ndata)
{
    SF_LNODE* q;
    if (!s->head)
    {
        q = s->tail = s->head = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        if (!q)
            return -1;
        q->ndata = (NODE_DATA)ndata;
        q->next = 0;
        q->prev = 0;
    }
    else
    {
        q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        if (!q)
            return -1;
        q->ndata = ndata;
        q->next = 0;
        q->prev = s->tail;
        s->tail->next = q;
        s->tail = q;
    }
    s->count++;

    return 0;
}

int sfqueue_add(SF_QUEUE* s, NODE_DATA ndata)
{
    return sflist_add_tail (s, ndata);
}

int sfstack_add(SF_STACK* s, NODE_DATA ndata)
{
    return sflist_add_tail (s, ndata);
}

/*
*   List walk - First/Next - return the node data or NULL
*/
NODE_DATA sflist_first(SF_LIST* s, SF_LNODE** v)
{
    if ( !s )
    {
        *v = nullptr;
        return nullptr;
    }

    *v = s->head;

    if ( *v )
        return (*v)->ndata;

    return nullptr;
}

NODE_DATA sflist_next(SF_LNODE** v)
{
    if ( v && *v )
    {
        *v = (*v)->next;
        if ( *v )
            return (*v)->ndata;
    }
    return nullptr;
}

/*
*  Remove Head Item from list
*/
NODE_DATA sflist_remove_head(SF_LIST* s)
{
    NODE_DATA ndata = 0;
    SF_QNODE* q;
    if ( s && s->head  )
    {
        q = s->head;
        ndata = q->ndata;
        s->head = s->head->next;
        s->count--;

        if ( !s->head  )
            s->tail = nullptr;
        else
            s->head->prev = nullptr;

        s_free(q);
    }
    return (NODE_DATA)ndata;
}

/*
*  Remove tail Item from list
*/
NODE_DATA sflist_remove_tail(SF_LIST* s)
{
    NODE_DATA ndata = 0;
    SF_QNODE* q;
    if (s && s->tail)
    {
        q = s->tail;

        ndata = q->ndata;
        s->count--;
        s->tail = q->prev;

        if (!s->tail)
            s->head = nullptr;
        else
            s->tail->next = nullptr;

        s_free (q);
    }
    return (NODE_DATA)ndata;
}

void sflist_remove_node(SF_LIST* s, SF_LNODE* n)
{
    SF_LNODE* cur;

    if ( n == s->head )
    {
        s->head = s->head->next;
        s->count--;

        if (!s->head)
            s->tail = nullptr;
        else
            s->head->prev = nullptr;

        s_free(n);
        return;
    }
    else if ( n == s->tail )
    {
        s->tail = s->tail->prev;
        s->count--;

        if (!s->tail )
            s->head = 0;
        else
            s->tail->next = nullptr;

        s_free(n);
        return;
    }

    for (cur = s->head;
        cur!= NULL;
        cur = cur->next )
    {
        if ( n == cur )
        {
            /* unlink a middle node */
            n->next->prev = n->prev;
            n->prev->next = n->next;
            s->count--;
            s_free(n);
            return;
        }
    }
}

/*
*  Remove Head Item from queue
*/
NODE_DATA sfqueue_remove(SF_QUEUE* s)
{
    return (NODE_DATA)sflist_remove_head(s);
}

/*
*  Remove Tail Item from stack
*/
NODE_DATA sfstack_remove(SF_QUEUE* s)
{
    return (NODE_DATA)sflist_remove_tail(s);
}

/*
*  COUNT
*/
int sfqueue_count(SF_QUEUE* s)
{
    if (!s)
        return 0;
    return s->count;
}

int sflist_count(SF_LIST* s)
{
    if (!s)
        return 0;
    return s->count;
}

int sfstack_count(SF_STACK* s)
{
    if (!s)
        return 0;
    return s->count;
}

/*
*   Free List + Free it's data nodes using 'nfree'
*/
void sflist_free_all(SF_LIST* s, void (* nfree)(void*) )
{
    void* p;

    if (!s)
        return;

    while ( s->count > 0 )
    {
        p = sflist_remove_head (s);

        if ( p && nfree )
            nfree(p);
    }
    s_free(s);
}

void sfqueue_free_all(SF_QUEUE* s,void (* nfree)(void*) )
{
    sflist_free_all(s, nfree);
}

void sfstack_free_all(SF_STACK* s,void (* nfree)(void*) )
{
    sflist_free_all(s, nfree);
}

void sflist_static_free_all(SF_LIST* s, void (* nfree)(void*) )
{
    void* p;

    if (!s)
        return;

    while ( s->count > 0 )
    {
        p = sflist_remove_head (s);

        if ( p && nfree )
            nfree(p);
    }
}

void sfqueue_static_free_all(SF_QUEUE* s,void (* nfree)(void*) )
{
    sflist_static_free_all(s, nfree);
}

void sfstack_static_free_all(SF_STACK* s,void (* nfree)(void*) )
{
    sflist_static_free_all(s, nfree);
}

/*
*  FREE List/Queue/Stack/Dictionary
*
*  This does not free a nodes data
*/
void sflist_free(SF_LIST* s)
{
    while ( sflist_count(s) )
    {
        sflist_remove_head(s);
    }
    s_free(s);
}

void sfqueue_free(SF_QUEUE* s)
{
    sflist_free (s);
}

void sfstack_free(SF_STACK* s)
{
    sflist_free (s);
}

/* Use these if the SF_LIST was not dynamically allocated via
 * sflist_new() */
void sflist_static_free(SF_LIST* s)
{
    while (sflist_count(s))
        sflist_remove_head(s);
}

void sfqueue_static_free(SF_QUEUE* s)
{
    sflist_static_free(s);
}

void sfstack_static_free(SF_STACK* s)
{
    sflist_static_free(s);
}

/*
*   Integer stack functions - for performance scenarios
*/
int sfistack_init(SF_ISTACK* s, unsigned* a,  unsigned n)
{
    if ( a )
        s->stack = a;
    else
    {
        s->stack = (unsigned*)calloc(n, sizeof(unsigned) );
    }
    if ( !s->stack )
        return -1;
    s->nstack= n;
    s->n =0;
    return 0;
}

int sfistack_push(SF_ISTACK* s, unsigned value)
{
    if ( s->n < s->nstack )
    {
        s->stack[s->n++] = value;
        return 0;
    }
    return -1;
}

int sfistack_pop(SF_ISTACK* s, unsigned* value)
{
    if ( s->n > 0 )
    {
        s->n--;
        *value = s->stack[s->n];
        return 0;
    }
    return -1;
}

/*
*  Pointer Stack Functions - for performance scenarios
*/
int sfpstack_init(SF_PSTACK* s, void** a,  unsigned n)
{
    if ( a )
        s->stack = a;
    else
    {
        s->stack = (void**)calloc(n, sizeof(void*) );
    }

    if ( !s->stack )
        return -1;
    s->nstack= n;
    s->n =0;
    return 0;
}

int sfpstack_push(SF_PSTACK* s, void* value)
{
    if ( s->n < s->nstack )
    {
        s->stack[s->n++] = value;
        return 0;
    }
    return -1;
}

int sfpstack_pop(SF_PSTACK* s, void** value)
{
    if ( s->n > 0 )
    {
        s->n--;
        *value = s->stack[s->n];
        return 0;
    }
    return -1;
}

