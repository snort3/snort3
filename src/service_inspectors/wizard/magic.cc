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
// magic.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "magic.h"

#include <cassert>

MagicPage::MagicPage(const MagicBook& b) : book(b)
{
    for ( int i = 0; i < 256; ++i )
        next[i] = nullptr;
    any = nullptr;
}

MagicPage::~MagicPage()
{
    for ( int i = 0; i < 256; ++i )
    {
        if ( next[i] && next[i] != this )
            delete next[i];
    }
    delete any;
}

const char* MagicBook::find_spell(const uint8_t* data, unsigned len, const MagicPage*& p) const
{
    assert(p);

    p = find_spell(data, len, p, 0);

    if ( p && !p->value.empty() )
        return p->value.c_str();

    return nullptr;
}

MagicBook::MagicBook()
{ root = new MagicPage(*this); }

MagicBook::~MagicBook()
{ delete root; }

