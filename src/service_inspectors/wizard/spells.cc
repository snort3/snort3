//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// spells.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "main/snort_config.h"

#include "magic.h"

using namespace snort;
using namespace std;

#define WILD 0x100

SpellBook::SpellBook() : glob(nullptr)
{
    // allows skipping leading whitespace only
    root->next[(int)' '] = root;
    root->next[(int)'\t'] = root;
    root->next[(int)'\r'] = root;
    root->next[(int)'\n'] = root;
}

bool SpellBook::translate(const char* in, HexVector& out)
{
    bool wild = false;
    unsigned i = 0;

    while ( in[i] )
    {
        if ( !isprint(in[i]) )
            return false;

        if ( wild )
        {
            if ( in[i] != '*' )
                out.emplace_back(WILD);

            out.emplace_back(in[i]);
            wild = false;
        }
        else
        {
            if ( in[i] == '*' )
                wild = true;
            else
                out.emplace_back(in[i]);
        }
        ++i;
    }
    return true;
}

void SpellBook::add_spell(
    const char* key, const char* val, HexVector& hv, unsigned i, MagicPage* p)
{
    while ( i < hv.size() )
    {
        MagicPage* t = new MagicPage(*this);

        if ( hv[i] == WILD )
            p->any = t;
        else
            p->next[toupper(hv[i])] = t;

        p = t;
        ++i;
    }
    p->key = key;
    p->value = SnortConfig::get_static_name(val);
}

bool SpellBook::add_spell(const char* key, const char*& val)
{
    HexVector hv;

    if ( !translate(key, hv) )
    {
        val = nullptr;
        return false;
    }

    unsigned i = 0;
    MagicPage* p = root;

    // Perform a longest prefix match before inserting the pattern.
    while ( i < hv.size() )
    {
        int c = toupper(hv[i]);

        if ( c == WILD && p->any )
            p = p->any;

        else if ( c != WILD && p->next[c] )
            p = p->next[c];

        else
            break;

        ++i;
    }
    if ( p->key == key )
    {
        val = p->value;
        return false;
    }

    add_spell(key, val, hv, i, p);
    return true;
}

const MagicPage* SpellBook::find_spell(
    const uint8_t* s, unsigned n, const MagicPage* p, unsigned i) const
{
    while ( i < n )
    {
        int c = toupper(s[i]);

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
            while ( i < n )
            {
                if ( const MagicPage* q = find_spell(s, n, p->any, i) )
                {
                    glob = q->any ? q : p;
                    return q;
                }
                ++i;
            }
            return p;
        }

        // If no match but has glob, continue lookup from glob
        if ( !p->value && glob )
        {
            p = glob;
            glob = nullptr;

            return find_spell(s, n, p, i);
        }

        return p->value ? p : nullptr;
    }
    return p;
}
