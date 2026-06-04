//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snapshot.h"

using namespace snort::stats;

bool snort::stats::is_zero(const Counter& counter)
{
    if ( std::get_if<std::monostate>(&counter.value) )
        return true;

    if ( const auto* value = std::get_if<bool>(&counter.value) )
        return !*value;

    if ( const auto* value = std::get_if<int64_t>(&counter.value) )
        return *value == 0;

    if ( const auto* value = std::get_if<uint64_t>(&counter.value) )
        return *value == 0;

    if ( const auto* value = std::get_if<double>(&counter.value) )
        return *value == 0.0;

    if ( const auto* value = std::get_if<std::string>(&counter.value) )
        return value->empty();

    return true;
}

bool snort::stats::should_render(const Counter& counter, const RenderOptions& options)
{
    return options.include_zeros || !is_zero(counter);
}
