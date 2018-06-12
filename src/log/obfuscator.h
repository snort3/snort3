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

// obfuscate.h author Victor Roemer <viroemer@cisco.com>

#ifndef OBFUSCATOR_H
#define OBFUSCATOR_H

#include <cstddef>
#include <cstdint>
#include <set>

#include "main/snort_types.h"

namespace snort
{
struct ObfuscatorBlock
{
    // Only used by `class Obfuscator`
    ObfuscatorBlock(uint32_t off, uint32_t len)
        : offset(off), length(len)
    { }

    // Used for iterations
    ObfuscatorBlock() = default;

    uint32_t offset;
    size_t length;
};

class SO_PUBLIC Obfuscator
{
public:
    struct BlockCompare
    {
        bool operator() (const ObfuscatorBlock& l, const ObfuscatorBlock& r) const
        { return l.offset < r.offset; }
    };

    using ObSet = std::set<ObfuscatorBlock, BlockCompare>;
    using const_iterator = ObSet::const_iterator;
    using iterator = ObSet::iterator;

    void push(uint32_t offset, uint32_t length)
    { blocks.emplace(offset, length); }

    const_iterator begin() const
    { return blocks.cbegin(); }

    const_iterator end() const
    { return blocks.cend(); }

    bool first(ObfuscatorBlock &b);
    bool next(ObfuscatorBlock &b);

    char get_mask_char()
    { return mask_char; }

private:
    ObSet blocks;
    iterator it;
    static const char mask_char = 'X';
};
}

#endif

