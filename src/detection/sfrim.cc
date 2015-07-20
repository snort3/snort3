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

// sfrim.c author Marc Norton
// modified to use a vector w/o a hard max

#include "sfrim.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>

#include "utils/util.h"

struct rule_number_t
{
    unsigned gid;
    unsigned sid;

    rule_number_t(unsigned g, unsigned s)
    { gid = g; sid = s; }
};

struct rule_index_map_t
{
    std::vector<rule_number_t> map;
};

rule_index_map_t* RuleIndexMapCreate()
{
    rule_index_map_t* rim = new rule_index_map_t;
    return rim;
}

void RuleIndexMapFree(rule_index_map_t* rim)
{
    assert(rim);
    delete rim;
}

int RuleIndexMapAdd(rule_index_map_t* rim, unsigned gid, unsigned sid)
{
    assert(rim);

    rule_number_t rn(gid, sid);
    int index = rim->map.size();
    rim->map.push_back(rn);

    //printf("RuleIndexMapping: index=%d gid=%u sid=%u\n",index,gid,sid);
    return index;
}

unsigned RuleIndexMapSid(rule_index_map_t* rim, int index)
{
    if ( rim and (unsigned)index < rim->map.size() )
    {
        return rim->map[index].sid;
    }
    return 0;
}

unsigned RuleIndexMapGid(rule_index_map_t* rim, int index)
{
    assert(rim);

    if ( (unsigned)index < rim->map.size() )
    {
        return rim->map[index].gid;
    }
    return 0;
}

void print_rule_index_map(rule_index_map_t* rim)
{
    assert(rim);
    printf("***\n*** Rule Index Map (%lu entries)\n***\n",rim->map.size());

    for (unsigned i=0; i<rim->map.size(); i++)
    {
        printf("rule-index-map[%d] { gid:%u sid:%u }\n",
            i,rim->map[i].gid,rim->map[i].sid);
    }
    printf("***end rule index map ***\n");
}

void rule_index_map_print_index(rule_index_map_t* rim, int index, char* buf, int bufsize)
{
    if ( (unsigned)index < rim->map.size() )
    {
        SnortSnprintfAppend(buf, bufsize, "%u:%u ",
            rim->map[index].gid, rim->map[index].sid);
    }
}

