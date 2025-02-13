//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

using namespace std;

#define WILD 0x100

SpellBook::SpellBook() : MagicBook()
{
    // applying for both TCP and UDP arrays
    for (size_t idx = 0; idx < (int)ArcaneType::MAX; ++idx)
    {
        MagicPage* r = &root[idx];

        // allows skipping leading whitespace only
        root[idx].next[(int)' '] = r;
        root[idx].next[(int)'\t'] = r;
        root[idx].next[(int)'\r'] = r;
        root[idx].next[(int)'\n'] = r;
    }
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
    const char* key, const char* val, const HexVector& hv, unsigned i, MagicPage* p)
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
    p->value = snort::SnortConfig::get_static_name(val);
}

bool SpellBook::add_spell(const char* key, const char*& val, ArcaneType proto)
{
    // In case of 'ANY' as proto, pattern should be added
    // to both UDP and TCP collections
    if ( proto == ArcaneType::ANY )
    {
        auto val_local = val;

        bool ret1 = add_spell(key, val_local, ArcaneType::UDP);
        bool ret2 = add_spell(key, val, ArcaneType::TCP);

        return ret1 || ret2;
    }

    HexVector hv;

    if ( !translate(key, hv) )
    {
        val = nullptr;

        return false;
    }

    unsigned i = 0;
    MagicPage* p = get_root(proto);

    // Perform a longest prefix match before inserting the pattern.
    while ( i < hv.size() )
    {
        int c = toupper(hv[i]);

        if ( c == WILD and p->any )
            p = p->any;

        else if ( c != WILD and p->next[c] )
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
    const uint8_t* s, unsigned n, const MagicPage* p, unsigned i, const MagicPage*& bookmark) const
{
    while ( i < n )
    {
        int c = toupper(s[i]);

        if ( p->next[c] )
        {
            if ( p->any )
            {
                if ( const MagicPage* q = find_spell(s, n, p->next[c], i+1, bookmark) )
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
                if ( const MagicPage* q = find_spell(s, n, p->any, i, bookmark) )
                {
                    bookmark = q->any ? q : p;

                    return q;
                }

                ++i;
            }

            return p;
        }

        // If no match but has bookmark, continue lookup from bookmark
        if ( !p->value and bookmark )
        {
            p = bookmark;
            bookmark = nullptr;

            return find_spell(s, n, p, i, bookmark);
        }

        return p->value ? p : nullptr;
    }

    return p;
}
