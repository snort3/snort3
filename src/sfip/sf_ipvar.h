//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
 * Adam Keeton
 * sf_ipvar.h
 * 11/17/06
*/

#ifndef SF_IPVAR_H
#define SF_IPVAR_H

// Supports basic IP variable operations
// Manages a doubly linked list of IP variables for the variable table

/* Flags */
#define SFIP_NEGATED  1
#define SFIP_ANY      2

#include <stdio.h>
#include "sfip/sf_ip.h"

/* Selects which mode a given variable is using to
 * store and lookup IP addresses */
typedef enum _modes
{
    SFIP_LIST,
    SFIP_TABLE
} MODES;

/* Used by the "list" mode.  A doubly linked list of sfip_t objects. */
typedef struct _ip_node
{
    sfip_t* ip;
#define ip_addr ip;   /* To ease porting Snort */
    struct _ip_node* next;
    int flags;
    // XXX
    int addr_flags; /* Flags used exlusively by Snort */
                    /* Keeping these variables seperate keeps
                     * this from stepping on Snort's toes. */
                    /* Should merge them later */
} sfip_node_t;

/* An IP variable onkect */
struct sfip_var_t
{
    /* Selects whether or not to use the list, the table,
     * or any other method added later */
    MODES mode;

    /* Linked lists.  Switch to something faster later */
    sfip_node_t* head;
    sfip_node_t* neg_head;

    /* The mode above will select whether to use the sfip_node_t linked list
     * or the IP routing table */
//    sfrt rt;

    /* Linked list of IP variables for the variable table */
    sfip_var_t* next;

    uint32_t id;
    char* name;
    char* value;
};

/* A variable table for storing and looking up variables
   Expand later to use a faster data structure */
struct vartable_t
{
    sfip_var_t* head;
    uint32_t id;
};

/* Creates a new variable that is an alias of another variable
 * Does a "deep" copy so it owns it's own pointers */
sfip_var_t* sfvar_create_alias(const sfip_var_t* alias_from, const char* alias_to);

/* Allocates a new variable as according to "str" */
sfip_var_t* sfvar_alloc(vartable_t* table, const char* str, SFIP_RET* status);

/* Makes sure there are no IP address conflicts in the variable
   Returns SFIP_CONFLICT if so */
SFIP_RET sfvar_validate(sfip_var_t* var);

/* Parses an IP list described by 'str' and saves the results in 'var'. */
SFIP_RET sfvar_parse_iplist(vartable_t* table, sfip_var_t* var,
    const char* str, int negation);

/* Compares two variables.  Necessary when building RTN structure */
SFIP_RET sfvar_compare(const sfip_var_t* one, const sfip_var_t* two);

/* Free an allocated variable */
void sfvar_free(sfip_var_t* var);

/* Returns non-zero if ip is contained in 'var', 0 otherwise
   If either argument is NULL, 0 is returned. */
int sfvar_ip_in(sfip_var_t* var, const sfip_t* ip);

#endif
