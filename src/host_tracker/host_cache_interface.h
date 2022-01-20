//--------------------------------------------------------------------------
// Copyright (C) 2016-2022 Cisco and/or its affiliates. All rights reserved.
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

// host_cache_interface.h author Silviu Minut <sminut@cisco.com>

#ifndef HOST_CACHE_INTERFACE_H
#define HOST_CACHE_INTERFACE_H

class HostCacheInterface
{
public:

    // This abstract class is the interface of the host cache for the allocator.
    //
    // Only the allocator calls update(), in the derived class. In turn,
    // the allocator is called, for instance, from HostTracker::add_service(),
    // which locks the host tracker but not the cache. Therefore, update()
    // must lock the cache.
    //
    // Note that any cache item object that is not yet owned by the cache
    // will increase / decrease the current_size of the cache any time it
    // adds / removes something to itself. Case in point: HostTracker.
    //
    // Therefore, if the cache items are containers that can grow dynamically,
    // then those items should be added to the cache first, and only accessed
    // via the cache. Then, any size change of the item, will legitimately
    // and correctly update the current_size of the cache.
    //
    // In concrete terms, never have a zombie HostTracker object outside
    // the host cache add or remove stuff to itself, as that will incorrectly
    // change the current_size of the cache.
    virtual void update(int size) = 0;
};

#endif
