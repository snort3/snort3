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
// sflsq.h author Marc Norton <mnorton@sourcefire.com>

#ifndef SFLSQ_H
#define SFLSQ_H

#include "main/snort_types.h"

// Simple LIST, STACK, QUEUE DICTIONARY (LIST BASED) interface
// All of these functions are based on lists.
// Use STL containers instead of these if possible.

// FIXIT-L if we're going to keep sflsq around (instead of using STL data
// structures) it would make sense to template the interfaces instead of
// using a void* for data

// FIXIT-M but we are going to delete sflsq and use STL instead

// Note that NODE_DATA can be redefined with the typedef below
typedef void* NODE_DATA;

// Simple list, stack, or queue NODE
typedef struct sf_lnode
{
    struct sf_lnode* next;
    struct sf_lnode* prev;
    NODE_DATA ndata;
}
SF_QNODE,SF_SNODE,SF_LNODE;

// Integer Stack - uses an array from the subroutines stack
struct SF_ISTACK
{
    unsigned* stack;
    unsigned nstack;
    unsigned n;
};

// Pointer Stack - uses an array from the subroutines stack
struct SF_PSTACK
{
    void** stack;
    unsigned nstack;
    unsigned n;
};

// Simple Structure for Queue's, stacks, lists
struct sf_list
{
    SF_LNODE* head, * tail;
    unsigned count;
};

typedef sf_list SF_QUEUE;
typedef sf_list SF_LIST;

// -----------------------------------------------------------------------------
// Linked List Interface
// -----------------------------------------------------------------------------
SO_PUBLIC SF_LIST* sflist_new();
SO_PUBLIC void sflist_init(SF_LIST*);
SO_PUBLIC void sflist_add_tail(SF_LIST*, NODE_DATA);
SO_PUBLIC void sflist_add_head(SF_LIST*, NODE_DATA);
SO_PUBLIC void sflist_add_before(SF_LIST*, SF_LNODE*, NODE_DATA);
SO_PUBLIC NODE_DATA sflist_remove_head(SF_LIST*);
SO_PUBLIC NODE_DATA sflist_remove_tail(SF_LIST*);
SO_PUBLIC void sflist_remove_node(SF_LIST*, SF_LNODE*);
SO_PUBLIC int sflist_count(SF_LIST*);
SO_PUBLIC NODE_DATA sflist_first(SF_LIST*, SF_LNODE**);
SO_PUBLIC NODE_DATA sflist_next(SF_LNODE**);
SO_PUBLIC void sflist_free(SF_LIST*);
SO_PUBLIC void sflist_free_all(SF_LIST*, void (* free)(void*) );
SO_PUBLIC void sflist_static_free_all(SF_LIST*, void (* nfree)(void*));

// -----------------------------------------------------------------------------
//  Queue Interface ( FIFO - First in, First out )
// -----------------------------------------------------------------------------
SF_QUEUE* sfqueue_new();
void sfqueue_add(SF_QUEUE*, NODE_DATA);
NODE_DATA sfqueue_remove(SF_QUEUE*);
int sfqueue_count(SF_QUEUE*);
void sfqueue_free_all(SF_QUEUE*, void (* free)(void*) );

#endif

