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

// active_context.h author Joel Cornett <jocornet@cisco.com>

#ifndef ACTIVE_CONTEXT_H
#define ACTIVE_CONTEXT_H

template<typename T>
class ActiveContext
{
public:
    constexpr ActiveContext() : fallback(), cur(nullptr) { }

    T* set(T* ctx)
    {
        auto tmp = cur;
        cur = ctx;
        return tmp;
    }

    T* unset()
    { return set(nullptr); }

    T* get()
    { return cur; }

    const T* get() const
    { return cur; }

    T& get_default()
    { return cur ? *cur : fallback; }

    const T& get_default() const
    { return cur ? *cur : fallback; }

    T& get_fallback()
    { return fallback; }

    const T& get_fallback() const
    { return fallback; }

    bool is_set() const
    { return cur != nullptr; }

private:
    T fallback;
    T* cur;
};

#endif
