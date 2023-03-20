//--------------------------------------------------------------------------
// Copyright (C) 2023-2023 Cisco and/or its affiliates. All rights reserved.
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

// heap_interface.cc author Russ Combs <rucombs@cisco.com>

#ifndef HEAP_INTERFACE_H
#define HEAP_INTERFACE_H

#include <cstdint>

class ControlConn;
namespace memory
{

class HeapInterface
{
public:
    virtual ~HeapInterface() { }

    virtual void main_init() = 0;
    virtual void thread_init() = 0;

    virtual void get_process_total(uint64_t& epoch, uint64_t& total) = 0;
    virtual void get_thread_allocs(uint64_t& alloc, uint64_t& dealloc) = 0;

    virtual void print_stats(ControlConn*) { }
    static HeapInterface* get_instance();

protected:
    HeapInterface() { }
};

}

#endif

