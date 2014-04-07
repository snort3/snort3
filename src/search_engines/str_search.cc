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

#include "str_search.h"

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "thread.h"
#include "framework/mpse.h"
#include "managers/mpse_manager.h"

typedef struct tag_search
{
    Mpse* mpse;
    unsigned int max_len;
} t_search;

void *  SearchInstanceNew(void)
{
    t_search * search = (t_search*)malloc(sizeof(t_search));
    if( !search )
        return NULL;

    search->mpse  = MpseManager::get_search_engine("ac_bnfa");

    if (search->mpse == NULL )
    {
        free(search);
        return NULL;
    }
    search->max_len=0;

    return search;
}

void SearchInstanceFree( void * instance )
{
    t_search * search = (t_search*)instance;
    if( instance )
    {
        MpseManager::delete_search_engine(search->mpse);
        free( instance );
    }
}

void SearchInstanceAdd(
    void*instance, const char *pat, unsigned int pat_len, int id)
{
    t_search * search = (t_search*)instance;

    if( search && search->mpse )
        search->mpse->add_pattern(
            NULL,  (void *)pat, pat_len, 1, 0, 0, 0, (void *)(long) id, 0);

    if ( search && pat_len > search->max_len )
         search->max_len = pat_len;

}
void SearchInstancePrepPatterns(void * instance)
{
    t_search * search = (t_search*)instance;
    if( search && search->mpse )
    {
        search->mpse->prep_patterns(NULL, NULL, NULL);
    }
}

int  SearchInstanceFindString(
    void * instance,
    const char *str,
    unsigned int str_len,
    int confine,
    int (*Match) (void *, void *, int, void *, void *))
{
    int num;
    int start_state = 0;
    t_search * search = (t_search*)instance;

    if ( confine && (search->max_len > 0) )
    {
        if ( search->max_len < str_len )
        {
            str_len = search->max_len;
        }
    }
    num = search->mpse->search(
        (unsigned char*)str, str_len, Match, (void *) str, &start_state);

    return num;

}

/* API exported by this module */
SearchAPI searchAPI =
{
    SearchInstanceNew,
    SearchInstanceFree,
    SearchInstanceAdd,
    SearchInstancePrepPatterns,
    SearchInstanceFindString,
};

SearchAPI *search_api = &searchAPI;

