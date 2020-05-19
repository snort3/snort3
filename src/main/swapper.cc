//--------------------------------------------------------------------------
// Copyright (C) 2016-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "target_based/host_attributes.h"

#include "analyzer.h"
#include "snort.h"
#include "snort_config.h"

using namespace snort;

bool Swapper::reload_in_progress = false;

Swapper::Swapper(SnortConfig* s, HostAttributesTable* t)
{
    old_conf = nullptr;
    new_conf = s;

    old_attribs = nullptr;
    new_attribs = t;
}

Swapper::Swapper(const SnortConfig* sold, SnortConfig* snew)
{
    old_conf = sold;
    new_conf = snew;

    old_attribs = nullptr;
    new_attribs = nullptr;
}

Swapper::Swapper(
    const SnortConfig* sold, SnortConfig* snew,
    HostAttributesTable* told, HostAttributesTable* tnew)
{
    old_conf = sold;
    new_conf = snew;

    old_attribs = told;
    new_attribs = tnew;
}

Swapper::Swapper(HostAttributesTable* told, HostAttributesTable* tnew)
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
        delete old_attribs;
}

void Swapper::apply(Analyzer& analyzer)
{
    if ( new_conf )
    {
        const bool reload = (SnortConfig::get_conf() != nullptr);
        SnortConfig::set_conf(new_conf);
        // FIXIT-M Determine whether we really want to do this before or after the set_conf
        if ( reload )
            analyzer.reinit(new_conf);
    }

    if ( new_attribs )
        HostAttributes::set_host_attributes_table(new_attribs);
}
