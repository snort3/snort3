//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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
// search_tool.h author Russ Combs <rucombs@cicso.com>

#ifndef SEARCH_TOOL_H
#define SEARCH_TOOL_H

#include "framework/mpse.h"

// FIXIT-L until APIs are updated, SearchTool depends on SnortConfig so it must
// not be instantiated until configure time (Inspector::configure) to ensure
// SnortConfig is fully initialized and the configured algorithm is used.

// Use hyperscan if configured with search_engine.search_method else use ac_full.
// Offload is not supported for search tool.

// We force non-hyperscan to be ac_full since the other algorithms like ac_bnfa
// don't implement search_all, which returns all patterns for a given match state.

namespace snort
{
class SO_PUBLIC SearchTool
{
public:
    SearchTool(bool multi_match = true);
    ~SearchTool();

    void add(const char* pattern, unsigned len, int s_id, bool no_case = true);
    void add(const char* pattern, unsigned len, void* s_context, bool no_case = true);

    void add(const uint8_t* pattern, unsigned len, int s_id, bool no_case = true);
    void add(const uint8_t* pattern, unsigned len, void* s_context, bool no_case = true);

    void prep();
    void reload();

    // set state to zero on first call
    int find(const char* s, unsigned s_len, MpseMatch, int& state,
        bool confine = false, void* user_data = nullptr);

    int find(const char* s, unsigned s_len, MpseMatch,
        bool confine = false, void* user_data = nullptr);

    int find_all(const char* s, unsigned s_len, MpseMatch,
        bool confine = false, void* user_data = nullptr);

private:
    class MpseGroup* mpsegrp;
    unsigned max_len;
    bool multi_match;
};
} // namespace snort
#endif

