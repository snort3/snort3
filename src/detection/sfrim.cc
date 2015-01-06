//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "sfrim.h"

/*
 *   sfrim.c
 *
 *   Rule Index Map
 *
 *   author: marc norton
 *
 */
#include <stdio.h>
#include <stdlib.h>

/*
 * Return Sid associated with index
 * author: marc norton
 */
unsigned RuleIndexMapSid( rule_index_map_t * map, int index )
{
    if( ! map )
        return 0;

    if( index < map->num_rules )
    {
        return map->map[index].sid;
    }
    return 0;
}
/*
 * Return Gid associated with index
 * author: marc norton
 */
unsigned RuleIndexMapGid(rule_index_map_t * map, int index )
{
    if( ! map )
    {
        return 0;
    }
    if( index < map->num_rules )
    {
        return map->map[index].gid;
    }
    return 0;
}
/*
 * Create a rule index map table
 * author: marc norton
 */
rule_index_map_t * RuleIndexMapCreate( int max_rules )
{
        rule_index_map_t *p = (rule_index_map_t*)calloc( 1, sizeof(rule_index_map_t) );
        if(!p)
        {
            return 0;
        }
        p->max_rules=max_rules;
        p->num_rules=0;
        p->map = (rule_number_t*)calloc( max_rules, sizeof(rule_number_t));
        if(!p->map )
        {
            free(p);
            return 0;
        }
        return p;
}
/*
 * Free a rule index map table
 * author: marc norton
 */
void RuleIndexMapFree( rule_index_map_t ** p )
{
    if( !p || !*p )
    {
      return ;
    }
    if( (*p)->map )
    {
        free((*p)->map);
    }
    free( *p );

    *p = 0;
}

/*
 * Add a rule to a rule index map table
 * author: marc norton
 */
int RuleIndexMapAdd( rule_index_map_t * p, unsigned gid, unsigned sid )
{
        int index;

        if( !p )
        {
            return -1;
        }
        if( p->num_rules == (p->max_rules - 1) )
        {
            return -1;
        }
        index = p->num_rules  ;
        p->map[ index ].gid = gid;
        p->map[ index ].sid = sid;
        p->num_rules++;

        //printf("RuleIndexMapping: index=%d gid=%u sid=%u\n",index,gid,sid);
        return index;
}
/*
 * print a rule index map table to stdout
 * author: marc norton
 */
void print_rule_index_map( rule_index_map_t * p )
{
    int i;
    printf("***\n*** Rule Index Map (%d entries)\n***\n",p->num_rules);
    for(i=0;i<p->num_rules;i++)
    {
         printf("rule-index-map[%d] { gid:%u sid:%u }\n",i,p->map[i].gid,p->map[i].sid);
    }
    printf("***end rule index map ***\n");
}

