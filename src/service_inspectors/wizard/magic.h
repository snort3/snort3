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
// magic.h author Russ Combs <rucombs@cisco.com>

#ifndef MAGIC_H
#define MAGIC_H

#include <cassert>
#include <string>
#include <vector>

class MagicBook;

struct MagicPage
{
    std::string key;
    const char* value = nullptr;

    MagicPage* next[256];
    MagicPage* any;

    const MagicBook& book;

    MagicPage(const MagicBook&);
    ~MagicPage();
};

typedef std::vector<uint16_t> HexVector;

// MagicBook is a set of MagicPages implementing a trie
class MagicBook
{
public:
    virtual ~MagicBook();

    MagicBook(const MagicBook&) = delete;
    MagicBook& operator=(const MagicBook&) = delete;

    enum class ArcaneType
    {
        TCP,
        UDP,
        ANY,
        MAX = ANY
    };

    virtual bool add_spell(const char* key, const char*& val, ArcaneType proto) = 0;
    virtual const char* find_spell(const uint8_t* data, unsigned len, const MagicPage*& p,
        const MagicPage*& bookmark) const;

    const MagicPage* page1(ArcaneType proto) const
    {
        assert(proto < ArcaneType::MAX);
        return &root[(int)proto];
    }

protected:
    MagicBook();
    MagicPage* root;

    MagicPage* get_root(ArcaneType proto) const
    {
        assert(proto < ArcaneType::MAX);
        return &root[(int)proto];
    }

    virtual const MagicPage* find_spell(const uint8_t*, unsigned,
        const MagicPage*, unsigned, const MagicPage*&) const = 0;
};

//-------------------------------------------------------------------------
// spells - a sequence of case insensitive text strings with wild cards
// designated by * (indicating any number of arbitrary bytes)
//-------------------------------------------------------------------------

class SpellBook : public MagicBook
{
public:
    SpellBook();

    bool add_spell(const char*, const char*&, ArcaneType) override;

private:
    bool translate(const char*, HexVector&);
    void add_spell(const char*, const char*, HexVector&, unsigned, MagicPage*);
    const MagicPage* find_spell(const uint8_t*, unsigned, const MagicPage*, unsigned,
        const MagicPage*&) const override;
};

//-------------------------------------------------------------------------
// hexes - a sequence of pipe delimited hex, text literals, and wild chars
// designated by '?' (indicating one arbitrary byte)
//-------------------------------------------------------------------------

class HexBook : public MagicBook
{
public:
    HexBook() = default;

    bool add_spell(const char*, const char*&, ArcaneType) override;

private:
    bool translate(const char*, HexVector&);
    void add_spell(const char*, const char*, HexVector&, unsigned, MagicPage*);
    const MagicPage* find_spell(const uint8_t*, unsigned, const MagicPage*, unsigned,
        const MagicPage*&) const override;
};

#endif

