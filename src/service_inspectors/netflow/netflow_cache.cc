//--------------------------------------------------------------------------
// Copyright (C) 2022-2023 Cisco and/or its affiliates. All rights reserved.
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

// netflow_cache.cc author Masud Hasan <mashasan@cisco.com>

#ifndef NETFLOW_CACHE_CC
#define NETFLOW_CACHE_CC

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netflow_cache.h"

THREAD_LOCAL NetFlowCache* netflow_cache = nullptr;

template <class T>
LruCacheAllocNetFlow<T>::LruCacheAllocNetFlow()
{
    lru = netflow_cache;
}

THREAD_LOCAL TemplateFieldCache* template_cache = nullptr;

template <class T>
LruCacheAllocTemplate<T>::LruCacheAllocTemplate()
{
    lru = template_cache;
}

#endif
