//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// lockless_ring.h author Cisco

#ifndef LOCKLESS_RING_H
#define LOCKLESS_RING_H

#include <atomic>
#include <cstdint>

static inline uint32_t round_up_to_power_of_2(uint32_t n)
{
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

enum SlotStatus : uint8_t
{
    SLOT_EMPTY = 0,
    SLOT_STORING = 1,
    SLOT_STORED = 2,
    SLOT_LOADING = 3
};


template<typename T, bool USE_MOVE_TO_DEQUEUE = true>
class LocklessRing
{
public:

    struct Slot
    {
        std::atomic<SlotStatus> status;
        T data;
        
        Slot() : status(SlotStatus::SLOT_EMPTY), data() {}
    };

    explicit LocklessRing(size_t capacity)
        : buf_cap(round_up_to_power_of_2(capacity))
        , buffer_(new Slot[buf_cap])
        , head_index(0)
        , tail_index(0)
    {
        for (size_t i = 0; i < buf_cap; ++i)
        {
            buffer_[i].status.store(SlotStatus::SLOT_EMPTY, std::memory_order_relaxed);
        }
    }

    ~LocklessRing()
    {
        delete[] buffer_;
    }

    inline void push(T&& item)
    {
        uint32_t current_head = head_index.fetch_add(1, std::memory_order_relaxed);
        do_push(std::forward<T>(item), &buffer_[current_head & (buf_cap - 1)]);
    } 

    inline bool try_push(const T& item)
    {
        auto current_head_index = head_index.load(std::memory_order_relaxed);

        do
        {
            if (static_cast<int32_t>(current_head_index - tail_index.load(std::memory_order_relaxed)) >= static_cast<int32_t>(buf_cap))
            {
                return false; // Buffer is full
            }
        } while (!head_index.compare_exchange_weak(current_head_index, current_head_index + 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed));

        do_push(T(item), &buffer_[current_head_index & (buf_cap - 1)]);
        return true;
    }

    inline bool try_push(T&& item)
    {
        auto current_head_index = head_index.load(std::memory_order_relaxed);

        do
        {
            if (static_cast<int32_t>(current_head_index - tail_index.load(std::memory_order_relaxed)) >= static_cast<int32_t>(buf_cap))
            {
                return false; // Buffer is full
            }
        } while (!head_index.compare_exchange_weak(current_head_index, current_head_index + 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed));

        do_push(std::forward<T>(item), &buffer_[current_head_index & (buf_cap - 1)]);
        return true;
    }

    inline auto pop()
    {
        uint32_t current_tail = tail_index.fetch_add(1, std::memory_order_relaxed);
        return do_pop(&buffer_[current_tail & (buf_cap - 1)]);
    }

    inline bool try_pop(T& item)
    {
        auto current_tail_index = tail_index.load(std::memory_order_relaxed);

        do
        {
            if (static_cast<int32_t>(head_index.load(std::memory_order_relaxed) - current_tail_index) <= 0)
            {
                return false; // Buffer is empty
            }
        }while(!tail_index.compare_exchange_weak(current_tail_index, current_tail_index + 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed));

        item = do_pop(&buffer_[current_tail_index & (buf_cap - 1)]);
        return true;
    }

    // Get approximate size
    uint32_t size() const
    {
        uint32_t head_pos = head_index.load(std::memory_order_relaxed);
        uint32_t tail_pos = tail_index.load(std::memory_order_relaxed);
        return head_pos >= tail_pos ? head_pos - tail_pos : head_pos + (UINT32_MAX - tail_pos);
    }

    // Check if empty
    bool is_empty() const
    {
        return size() == 0;
    }

    Slot* get_buffer(uint32_t& cur_tail)
    {
        cur_tail = tail_index.load(std::memory_order_relaxed) & (buf_cap - 1);
        return buffer_;
    }

    void reset()
    {
        head_index.store(0, std::memory_order_relaxed);
        tail_index.store(0, std::memory_order_relaxed);
        for (size_t i = 0; i < buf_cap; ++i)
        {
            buffer_[i].status.store(SlotStatus::SLOT_EMPTY, std::memory_order_relaxed);
        }
    }

private:

    inline T do_pop(Slot* slot)
    {
        for (;;)
        {
            SlotStatus expected_slot_status = SlotStatus::SLOT_STORED;
            if (slot->status.compare_exchange_weak(expected_slot_status, SlotStatus::SLOT_LOADING,
                                              std::memory_order_acquire,
                                              std::memory_order_relaxed))
            {
                if (USE_MOVE_TO_DEQUEUE)
                {
                    T item = std::move(slot->data);
                    slot->status.store(SlotStatus::SLOT_EMPTY, std::memory_order_release);
                    return item;
                }
                else
                {
                    T item = slot->data;
                    slot->status.store(SlotStatus::SLOT_EMPTY, std::memory_order_release);
                    return item;
                }
            }
        }
    }

    inline void do_push(T&& item, Slot* slot)
    {
        for (;;)
        {
            SlotStatus expected_slot_status = SlotStatus::SLOT_EMPTY;
            if (slot->status.compare_exchange_weak(expected_slot_status, SlotStatus::SLOT_STORING,
                                              std::memory_order_acquire,
                                              std::memory_order_relaxed))
            {
                slot->data = std::move(item);
                slot->status.store(SlotStatus::SLOT_STORED, std::memory_order_release);
                return;
            }
        }
    }

    const uint32_t buf_cap;
    Slot* buffer_;
    
    alignas(32) std::atomic<uint32_t> head_index;
    alignas(32) std::atomic<uint32_t> tail_index;

    static constexpr bool use_move_to_dequeue = USE_MOVE_TO_DEQUEUE;
};

#endif // LOCKLESS_RING_H
