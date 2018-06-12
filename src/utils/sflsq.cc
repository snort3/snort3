//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
*   Simple list, queue, and dictionary implementations
*   ( most of these implementations are list based - not performance monsters,
*     and they all use snort_alloc via s_alloc/s_free )
*
*   11/05/2005 - man - Added sflist_firstx() and sflist_nextx() with user
*   provided SF_NODE inputs for tracking the list position.  This allows
*   multiple readers to traverse a list.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sflsq.h"

#include "util.h"

// private alloc
static void* s_alloc(size_t n)
{
    return snort_calloc(n);
}

/*
*  private free
*/
static void s_free(void* p)
{
    if ( p )
        snort_free(p);
}

namespace snort
{
SF_LIST* sflist_new()
{
    SF_LIST* s;
    s = (SF_LIST*)s_alloc(sizeof(SF_LIST) );
    sflist_init(s);
    return s;
}

void sflist_init(SF_LIST* s)
{
    s->count=0;
    s->head = s->tail = nullptr;
}

void sflist_add_before(SF_LIST* s, SF_LNODE* lnode, NODE_DATA ndata)
{
    SF_LNODE* q;

    if ( lnode )
    {
        /* Add to head of list */
        if ( s->head == lnode )
            sflist_add_head (s, ndata);
        else
        {
            q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE) );
            q->ndata = (NODE_DATA)ndata;
            q->next = lnode;
            q->prev = lnode->prev;
            lnode->prev->next = q;
            lnode->prev       = q;
            s->count++;
        }
    }
}

void sflist_add_head(SF_LIST* s, NODE_DATA ndata)
{
    SF_LNODE* q;
    if (!s->head)
    {
        q = s->tail = s->head = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        q->ndata = (NODE_DATA)ndata;
        q->next = nullptr;
        q->prev = nullptr;
    }
    else
    {
        q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        q->ndata = ndata;
        q->next = s->head;
        q->prev = nullptr;
        s->head->prev = q;
        s->head = q;
    }
    s->count++;
}

void sflist_add_tail(SF_LIST* s, NODE_DATA ndata)
{
    SF_LNODE* q;
    if (!s->head)
    {
        q = s->tail = s->head = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        q->ndata = (NODE_DATA)ndata;
        q->next = nullptr;
        q->prev = nullptr;
    }
    else
    {
        q = (SF_LNODE*)s_alloc (sizeof (SF_LNODE));
        q->ndata = ndata;
        q->next = nullptr;
        q->prev = s->tail;
        s->tail->next = q;
        s->tail = q;
    }
    s->count++;
}

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

NODE_DATA sflist_remove_head(SF_LIST* s)
{
    NODE_DATA ndata = nullptr;
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

NODE_DATA sflist_remove_tail(SF_LIST* s)
{
    NODE_DATA ndata = nullptr;
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
            s->head = nullptr;
        else
            s->tail->next = nullptr;

        s_free(n);
        return;
    }

    for (cur = s->head;
        cur!= nullptr;
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

int sflist_count(SF_LIST* s)
{
    if (!s)
        return 0;
    return s->count;
}

void sflist_free(SF_LIST* s)
{
    while ( sflist_count(s) )
    {
        sflist_remove_head(s);
    }
    s_free(s);
}

void sflist_free_all(SF_LIST* s, void (* nfree)(void*) )
{
    if (!s)
        return;

    while ( s->count > 0 )
    {
        void* p = sflist_remove_head (s);

        if ( p && nfree )
            nfree(p);
    }
    s_free(s);
}

void sflist_static_free_all(SF_LIST* s, void (* nfree)(void*) )
{
    if (!s)
        return;

    while ( s->count > 0 )
    {
        void* p = sflist_remove_head (s);

        if ( p && nfree )
            nfree(p);
    }
}

}

// ----- queue methods -----

using namespace snort;

SF_QUEUE* sfqueue_new()
{
    return (SF_QUEUE*)sflist_new();
}

void sfqueue_add(SF_QUEUE* s, NODE_DATA ndata)
{
    sflist_add_tail (s, ndata);
}


NODE_DATA sfqueue_remove(SF_QUEUE* s)
{
    return (NODE_DATA)sflist_remove_head(s);
}

int sfqueue_count(SF_QUEUE* s)
{
    if (!s)
        return 0;
    return s->count;
}

void sfqueue_free_all(SF_QUEUE* s,void (* nfree)(void*) )
{
    sflist_free_all(s, nfree);
}


