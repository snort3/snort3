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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "obfuscator.h"

using namespace snort;

bool Obfuscator::first(ObfuscatorBlock &b)
{
    if ( blocks.empty() )
        return false;
    it = blocks.begin();
    b = *it;
    return true;
}

bool Obfuscator::next(ObfuscatorBlock &b)
{
    if ( blocks.empty() )
        return false;
    if ( it == blocks.end() )
        return false;
    if ( ++it == blocks.end() )
        return false;
    b = *it;
    return true;
}

