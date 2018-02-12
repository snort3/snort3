//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// magic.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>

#include "magic.h"

using namespace std;

#define WILD 0x100

bool HexBook::translate(const char* in, HexVector& out)
{
    bool hex = false;
    string byte;
    unsigned i = 0;

    while ( in[i] )
    {
        bool push = false;

        if ( in[i] == '|' )
        {
            hex = !hex;
            push = true;
        }
        else if ( !hex )
        {
            if ( in[i] == '?' )
                out.push_back(WILD);
            else
                out.push_back(in[i]);
        }
        else if ( in[i] != ' ' )
        {
            if ( !isxdigit(in[i]) || byte.size() > 1 )
                return false;

            byte += in[i];
        }
        else
            push = true;

        if ( push && !byte.empty() )
        {
            int b = strtol(byte.c_str(), nullptr, 16);
            out.push_back((uint8_t)b);
            byte.clear();
        }
        ++i;
    }
    return true;
}

//-------------------------------------------------------------------------

void HexBook::add_spell(
    const char* key, const char* val, HexVector& hv, unsigned i, MagicPage* p)
{
    while ( i < hv.size() )
    {
        MagicPage* t = new MagicPage(*this);
        int c = hv[i];

        if ( c == WILD )
            p->any = t;
        else
            p->next[c] = t;

        p = t;
        ++i;
    }
    p->key = key;
    p->value = val;
}

bool HexBook::add_spell(const char* key, const char* val)
{
    HexVector hv;

    if ( !translate(key, hv) )
        return false;

    unsigned i = 0;
    MagicPage* p = root;

    while ( i < hv.size() )
    {
        int c = hv[i];

        if ( c == WILD && p->any )
            p = p->any;

        else if ( p->next[c] )
            p = p->next[c];

        else
            break;

        ++i;
    }
    if ( p->key == key )
        return false;

    add_spell(key, val, hv, i, p);
    return true;
}

const MagicPage* HexBook::find_spell(
    const uint8_t* s, unsigned n, const MagicPage* p, unsigned i) const
{
    while ( i < n )
    {
        int c = s[i];

        if ( p->next[c] )
        {
            if ( p->any )
            {
                if ( const MagicPage* q = find_spell(s, n, p->next[c], i+1) )
                    return q;
            }
            else
            {
                p = p->next[c];
                ++i;
                continue;
            }
        }
        if ( p->any )
        {
            if ( const MagicPage* q = find_spell(s, n, p->any, i+1) )
                return q;
        }
        break;
    }
    return p;
}

const char* HexBook::find_spell(
    const uint8_t* data, unsigned len, const MagicPage*& p) const
{
    p = find_spell(data, len, p, 0);

    if ( !p->value.empty() )
        return p->value.c_str();

    return nullptr;
}

