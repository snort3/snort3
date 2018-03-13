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

#ifndef SEARCH_COMMON_H
#define SEARCH_COMMON_H

namespace snort
{
    struct SnortConfig;
}

struct MpseAgent
{
    int (* build_tree)(snort::SnortConfig*, void* id, void** tree);
    int (* negate_list)(void* id, void** list);

    void (* user_free)(void*);
    void (* tree_free)(void**);
    void (* list_free)(void**);
};

// interface to Mpse and SearchTool

typedef int (* MpseMatch)(void* user, void* tree, int index, void* context, void* list);

#endif

