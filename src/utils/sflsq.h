//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// Simple LIST interface
// Switch to STL containers ASAP
// FIXIT-M deprecated, we are going to delete this

typedef void* NODE_DATA;

typedef struct sf_lnode
{
    struct sf_lnode* next;
    struct sf_lnode* prev;
    NODE_DATA ndata;
}
SF_LNODE;

struct sf_list
{
    SF_LNODE* head, * tail;
    unsigned count;
};

typedef sf_list SF_LIST;

// -----------------------------------------------------------------------------
// Linked List Interface
// -----------------------------------------------------------------------------

namespace snort
{
SO_PUBLIC SF_LIST* sflist_new();
SO_PUBLIC void sflist_init(SF_LIST*);
SO_PUBLIC void sflist_add_tail(SF_LIST*, NODE_DATA);
SO_PUBLIC void sflist_add_head(SF_LIST*, NODE_DATA);
SO_PUBLIC void sflist_add_before(SF_LIST*, SF_LNODE*, NODE_DATA);
SO_PUBLIC NODE_DATA sflist_remove_head(SF_LIST*);
SO_PUBLIC NODE_DATA sflist_remove_tail(SF_LIST*);
SO_PUBLIC int sflist_count(SF_LIST*);
SO_PUBLIC NODE_DATA sflist_first(const SF_LIST*, SF_LNODE**);
SO_PUBLIC NODE_DATA sflist_next(SF_LNODE**);
SO_PUBLIC void sflist_free(SF_LIST*);
SO_PUBLIC void sflist_free_all(SF_LIST*, void (* free)(void*) );
SO_PUBLIC void sflist_static_free_all(SF_LIST*, void (* nfree)(void*));
}

#endif

