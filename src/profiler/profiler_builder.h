//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

// profiler_builder.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_BUILDER_H
#define PROFILER_BUILDER_H

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include "profiler_nodes.h"

class ProfilerNode;

template<typename Entry>
class ProfilerBuilder
{
public:
    using IncludeFn = std::function<bool(const ProfilerNode&)>;
    using SortFn = std::function<bool(const Entry&, const Entry&)>;

    struct Config
    {
        IncludeFn* include_fn = nullptr;
        SortFn* sort_fn = nullptr;
        unsigned max_entries = 0;
    };

    ProfilerBuilder(Config config) :
        config { config } { }

    void build(Entry& entry)
    {
        for ( const auto* child_node : entry.child_nodes() )
            if ( include(*child_node) )
                entry.child_entries().emplace_back(*child_node, entry.node);

        sort(entry.child_entries());

        for ( auto& child_entry : entry.child_entries() )
            build(child_entry);
    }

private:
    bool include(const ProfilerNode& node)
    { return !config.include_fn || (*config.include_fn)(node); }

    template<typename Container>
    void sort(Container& entries)
    {
        if ( !config.sort_fn )
            return;

        auto stop =
            ( !config.max_entries || config.max_entries >= entries.size() ) ?
            entries.end() :
            entries.begin() + config.max_entries;

        std::partial_sort(entries.begin(), stop, entries.end(), *config.sort_fn);
    }

    Config config;
};

#endif
