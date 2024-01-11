//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// memory_overloads.h author Sunirmal Mukherjee<sunimukh@cisco.com>

#ifndef MEMORY_OVERLOADS_H
#define MEMORY_OVERLOADS_H

#include <new>

// -----------------------------------------------------------------------------
// new /delete replacements
// -----------------------------------------------------------------------------

// these don't have to be visible to operate as replacements


void* operator new(std::size_t);
void* operator new[](std::size_t);
void* operator new(std::size_t, const std::nothrow_t&) noexcept;
void* operator new[](std::size_t, const std::nothrow_t&) noexcept;
void operator delete(void*) noexcept;
void operator delete[](void*) noexcept;
void operator delete(void*, const std::nothrow_t&) noexcept;
void operator delete[](void*, const std::nothrow_t&) noexcept;
void operator delete(void*, std::size_t) noexcept;
void operator delete[](void*, std::size_t) noexcept;
void operator delete[](void*, std::size_t, const std::nothrow_t&) noexcept;
void operator delete(void*, std::size_t, const std::nothrow_t&) noexcept;

#endif
