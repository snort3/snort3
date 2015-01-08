//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// range.cc author Russ Combs <rucombs@cisco.com>

#include "framework/range.h"

#include <stdlib.h>
#include <string.h>

#include <string>

void RangeCheck::init()
{
    op = MAX;
    min = max = 0;
}

bool RangeCheck::operator==(const RangeCheck& rhs) const
{
    return (op == rhs.op) && (min == rhs.min) && (max == rhs.max);
}

static RangeCheck::Op get_op(const char* s, unsigned n)
{
    if ( !strncmp(s, "=", n) && n == 1 )
        return RangeCheck::EQ;

    if ( !strncmp(s, "!", n) && n == 1 )
        return RangeCheck::NOT;

    if ( !strncmp(s, "<", n) && n == 1 )
        return RangeCheck::LT;

    if ( !strncmp(s, ">", n) && n == 1 )
        return RangeCheck::GT;

    if ( !strncmp(s, "!=", n) && n == 2 )
        return RangeCheck::NOT;

    if ( !strncmp(s, "<=", n) && n == 2 )
        return RangeCheck::LE;

    if ( !strncmp(s, ">=", n) && n == 2 )
        return RangeCheck::GE;

    if ( !strncmp(s, "<>", n) && n == 2 )
        return RangeCheck::LG;

    if ( !strncmp(s, "<=>", n) && n == 3 )
        return RangeCheck::LEG;

    return RangeCheck::MAX;
}

bool RangeCheck::parse(const char* s) 
{
    min = max = 0;
    char* enda = nullptr, * endb = nullptr;

    while ( *s == ' ' )
        ++s;

    const char* so = strpbrk(s, "=!<>");
    const char* sa = s;
    const char* sb = so;

    if ( !so )
    {
        op = EQ;
        min = strtol(sa, &enda, 0);
    }
    else
    {
        sb = so + 1;

        while ( strchr("=!<>", *sb) )
            ++sb;

        op = get_op(so, sb-so);
    }

    long a = 0, b = 0;

    if ( sa != so )
        a = strtol(sa, &enda, 0);

    if ( sb != so )
        b = strtol(sb, &endb, 0);

    if ( enda )
    {
        while ( *enda == ' ' )
            ++enda;
    }
    if ( endb )
    {
        while ( *endb == ' ' )
            ++endb;
    }
    if ( (enda && *enda && enda != so) || (endb && *endb) )
        return false;

    if ( op == MAX )
        return false;

    // need to validate that min and b were obtained iff
    // expected eg a!b should not have a, <>b is missing a

    // set bounds based on op
    switch ( op )
    {
    case EQ:
        min = sa ? a : b;
        break;
    case NOT:
    case GT:
    case GE:
        min = b;
        break;
    case LT:
    case LE:
        max = b;
        break;
    case LG:
    case LEG:
        min = a;
        max = b;
        break;
    default:
        break;
    }

    return true;
}

bool RangeCheck::eval(long c)
{
    switch ( op )
    {
    case EQ:
        return ( min == c );

    case NOT:
        return ( min != c );

    case LT:
        return ( c < max );

    case LE:
        return ( c <= max );

    case GT:
        return ( c > min );

    case GE:
        return ( c >= min );

    case LG:
        return ( min < c && c < max );

    case LEG:
        return ( min <= c && c <= max );

    default:
        break;
    }
    return false;
}

