//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// profiler_tree_builder.h author Joel Cornett <jocornet@cisco.com>

#ifndef PROFILER_TREE_BUILDER_H
#define PROFILER_TREE_BUILDER_H

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include "profiler_nodes.h"

template<typename View>
class ProfilerBuilder
{
public:

    struct Entry
    {
        View view;
        std::vector<Entry> children;

        bool operator==(const Entry& rhs) const
        { return view == rhs.view; }

        bool operator!=(const Entry& rhs) const
        { return !(*this == rhs); }

        Entry(const ProfilerNode& node, View* parent = nullptr) :
            view(node, parent) { }
    };

    using IncludeFn = std::function<bool(const ProfilerNode&)>;

    ProfilerBuilder(const IncludeFn& include) :
        include(include) { }

    Entry build(const ProfilerNode& node)
    {
        Entry root(node);
        build(root, node);
        return root;
    }

private:
    void build(Entry& entry, const ProfilerNode& cur)
    {
        for ( const auto* node : cur.get_children() )
            if ( include(*node) )
            {
                entry.children.emplace_back(*node, &entry.view);
                build(entry.children.back(), *node);
            }
    }

    const IncludeFn include;
};

#endif
