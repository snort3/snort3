//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfrim.h"

#include <cassert>
#include <vector>

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

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

bool RuleIndexMapGet(rule_index_map_t* rim, int index, unsigned& gid, unsigned& sid)
{
    if ( rim and (unsigned)index < rim->map.size() )
    {
        gid = rim->map[index].gid;
        sid = rim->map[index].sid;
        return true;
    }
    gid = sid = 0;
    return false;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("basic", "[RuleIndexMap]")
{
    rule_index_map_t* rim = RuleIndexMapCreate();
    unsigned gid, sid;

    CHECK((RuleIndexMapAdd(rim, 1, 2) == 0));
    CHECK((RuleIndexMapAdd(rim, 2, 4) == 1));
    CHECK((RuleIndexMapAdd(rim, 4, 8) == 2));

    SECTION("valid")
    {
        CHECK((RuleIndexMapGet(rim, 1, gid, sid) == true));

        CHECK((gid == 2));
        CHECK((sid == 4));
    }
    SECTION("invalid")
    {
        CHECK((RuleIndexMapGet(rim, 3, gid, sid) == false));

        CHECK((gid == 0));
        CHECK((sid == 0));
    }
    RuleIndexMapFree(rim);
}

#endif

