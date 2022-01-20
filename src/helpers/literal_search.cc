//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// literal_search.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "literal_search.h"

#include <cstring>

#include "main/snort_config.h"
#include "boyer_moore_search.h"
#include "hyper_search.h"

namespace snort
{

// setup and cleanup for hyperscan are independent of configuration
// because that would create a bad dependency - a module ctor needs
// a config item from a module.  also, the handle must persist for
// for the lifetime of a module, which can span many configs.

LiteralSearch::Handle* LiteralSearch::setup()
{
#ifdef HAVE_HYPERSCAN
    return HyperSearch::setup();
#else
    return nullptr;
#endif
}

void LiteralSearch::cleanup(LiteralSearch::Handle* h)
{
#ifdef HAVE_HYPERSCAN
    HyperSearch::cleanup(h);
#else
    UNUSED(h);
#endif
}

LiteralSearch* LiteralSearch::instantiate(
    LiteralSearch::Handle* h, const uint8_t* pattern, unsigned pattern_len, bool no_case, bool hs)
{
#ifdef HAVE_HYPERSCAN
    if ( hs or SnortConfig::get_conf()->hyperscan_literals )
        return new HyperSearch(h, pattern, pattern_len, no_case);
#else
    UNUSED(h);
    UNUSED(hs);
#endif
    if ( no_case )
        return new snort::BoyerMooreSearchNoCase(pattern, pattern_len);

    return new snort::BoyerMooreSearchCase(pattern, pattern_len);
}

}

