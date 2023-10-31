//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// primed_allocator.h author Carter Waxman <cwaxman@cisco.com>

#ifndef PRIMED_ALLOCATOR_H
#define PRIMED_ALLOCATOR_H

// An STL list allocator that pools deallocs on a freelist but only frees memory at destruction.
// Use this for containers where the maximum size is somehow capped but where storage may not reach
// that cap. This prevents unnecessary memory allocation but still provides the speed benefit of
// not repeatedly allocating memory. Additionally, the free list may be shared among multiple
// STL lists of the same type.

namespace snort
{
template<typename T>
class PrimedAllocator
{
public:
    struct Node
    {
        Node* next;
    };

    struct State
    {
        Node* free_list = nullptr;
        unsigned ref_count = 0;

        ~State()
        {
            while ( free_list )
            {
                Node* next = free_list->next;
                delete free_list;
                free_list = next;
            }
        }
    };

    using size_type = std::size_t;
    using pointer = T*;
    using const_pointer = const T*;
    using value_type = T;

    template<typename U> struct rebind { typedef PrimedAllocator<U> other; };

    PrimedAllocator() noexcept
    { state = new State; }

    // cppcheck-suppress copyCtorPointerCopying
    PrimedAllocator(const PrimedAllocator& other) noexcept : state(other.state)
    {
        state->ref_count++;
    }

    ~PrimedAllocator()
    {
        state->ref_count--;

        if ( !state->ref_count )
            delete state;
    }

    void set_state(State* state)
    {
        this->state->ref_count--;

        if ( !this->state->ref_count )
            delete state;

        this->state = state;
        state->ref_count++;
    }

    State* get_state() const
    { return state; }

    pointer allocate(size_type, const_pointer = 0)
    {
        if ( state->free_list )
        {
            T* ret = reinterpret_cast<T*>(state->free_list);
            state->free_list = state->free_list->next;
            return ret;
        }
        return reinterpret_cast<T*>(operator new(sizeof(T)));
    }

    void deallocate(pointer p, size_type) noexcept
    {
        Node* node = reinterpret_cast<Node*>(p);
        node->next = state->free_list;
        state->free_list = node;
    }

private:
    State* state;
};
}

#endif
