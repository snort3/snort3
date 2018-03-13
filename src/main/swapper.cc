//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// swapper.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swapper.h"

#include "target_based/sftarget_reader.h"

#include "snort_config.h"

using namespace snort;

bool Swapper::reload_in_progress = false;

Swapper::Swapper(SnortConfig* s, tTargetBasedConfig* t)
{
    old_conf = nullptr;
    new_conf = s;

    old_attribs = nullptr;
    new_attribs = t;
}

Swapper::Swapper(SnortConfig* sold, SnortConfig* snew)
{
    old_conf = sold;
    new_conf = snew;

    old_attribs = nullptr;
    new_attribs = nullptr;
}

Swapper::Swapper(SnortConfig* sold, SnortConfig* snew, tTargetBasedConfig* told, tTargetBasedConfig* tnew)
{
    old_conf = sold;
    new_conf = snew;

    old_attribs = told;
    new_attribs = tnew;
}

Swapper::Swapper(tTargetBasedConfig* told, tTargetBasedConfig* tnew)
{
    old_conf = nullptr;
    new_conf = nullptr;

    old_attribs = told;
    new_attribs = tnew;
}

Swapper::~Swapper()
{
    if ( old_conf )
        delete old_conf;

    if ( old_attribs )
        SFAT_Free(old_attribs);
}

void Swapper::apply()
{
    if ( new_conf )
        snort::SnortConfig::set_conf(new_conf);

    if ( new_attribs )
        SFAT_SetConfig(new_attribs);
}
