/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#ifndef STR_SEARCH_H
#define STR_SEARCH_H

typedef int (*MatchFunction)(void *, void *, int, void *, void *);

typedef struct _search_api
{
    void * (*search_instance_new)(void);
    void   (*search_instance_free)(void * instance);
    void   (*search_instance_add) (void * instance, const char *s, unsigned int s_len, int s_id);
    void   (*search_instance_prep)(void * instance );
    int    (*search_instance_find)(void * instance, const char *s, unsigned int s_len, int confine, MatchFunction); 
    
} SearchAPI;

// FIXIT search_api should be turned into a class
// (constructed of an Mpse, not subclassed)
extern SearchAPI *search_api;

#endif
