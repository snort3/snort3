//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// ring2.h author Cisco

#ifndef RING2_H
#define RING2_H

#include <atomic>
#include <cassert>
#include <cstring>

// Ring buffer implementation with the following requirements:
//     - stored objects are contiguous in memory
//     - stored record is length-value pair, where length is private
//     - 1 reader 1 writer are supported
//     - reader and writer can be in different threads, but their ops are still thread-local
//     - in case of overflow the new object is dropped (no overwrites)
//     - FIFO
//     - read operation grants direct access (no copy)
//     - container may contain gaps (not reaching full capacity)

class Ring2
{
public:
    struct Writer
    {
        Writer(Writer&& w) : ptr(w.ptr), end(w.end), store(w.store), no_turns(w.no_turns) {}

        void retry();                       // reinitialize writer
        bool write(const void*, size_t);    // adds another record
        void push();                        // publishes new records

    private:
        friend Ring2;

        Writer(Ring2& owner, uint8_t* cursor, uint8_t* guard, bool no_wrapping)
            : ptr(cursor), end(guard), store(owner), no_turns(no_wrapping) {}

        Writer& operator=(Writer&&);

        uint8_t* ptr;
        uint8_t* end;
        Ring2& store;
        bool no_turns;
    };

    struct Reader
    {
        Reader(Reader&& r ) : ptr(r.ptr), end(r.end), store(r.store), more_turns(r.more_turns) {}

        void retry();                       // reinitialize reader
        void* read(size_t&);                // gets next record
        void pop();                         // releases read records

    private:
        friend Ring2;

        Reader(Ring2& owner, uint8_t* cursor, uint8_t* guard, bool wrapping)
            : ptr(cursor), end(guard), store(owner), more_turns(wrapping) {}

        Reader& operator=(Reader&&);

        uint8_t* ptr;
        uint8_t* end;
        Ring2& store;
        bool more_turns;
    };

    Ring2(size_t);
    ~Ring2();

    Ring2(const Ring2&) = delete;
    Ring2& operator =(const Ring2&) = delete;

    size_t capacity() const;
    bool empty() const;
    void clear();                           // invalidates Reader and Writer unless they retry

    Writer writer();
    Reader reader();

    bool native(const Writer& w) const
    { return this == &w.store; }

    bool native(const Reader& r) const
    { return this == &r.store; }

private:
    using LEN_TYPE = uint32_t;
    static constexpr auto LEN_SIZE = sizeof(LEN_TYPE);

    uint8_t* const store;
    uint8_t* const store_end;
    std::atomic<uint8_t*> write_ptr;
    std::atomic<uint8_t*> read_ptr;
};

inline Ring2::Ring2(size_t buffer_size)
    : store(new uint8_t[buffer_size]), store_end(store + buffer_size)
{
    write_ptr.store(store, std::memory_order_relaxed);
    read_ptr.store(store, std::memory_order_relaxed);
}

inline Ring2::~Ring2()
{
    delete[] store;
}

inline size_t Ring2::capacity() const
{
    return store_end - store;
}

inline bool Ring2::empty() const
{
    auto w = write_ptr.load(std::memory_order_acquire);
    auto r = read_ptr.load(std::memory_order_acquire);

    return w == r;
}

inline void Ring2::clear()
{
    write_ptr.store(store, std::memory_order_relaxed);
    read_ptr.store(store, std::memory_order_relaxed);
}

inline Ring2::Writer Ring2::writer()
{
    auto w = write_ptr.load(std::memory_order_acquire);
    auto r = read_ptr.load(std::memory_order_acquire);

    auto no_wrapping = w < r;
    auto guard = no_wrapping ? r : store_end;

    return {*this, w, guard, no_wrapping};
}

inline Ring2::Reader Ring2::reader()
{
    auto w = write_ptr.load(std::memory_order_acquire);
    auto r = read_ptr.load(std::memory_order_acquire);

    auto wrapping = r > w;
    auto guard = wrapping ? store_end : w;

    return {*this, r, guard, wrapping};
}

inline bool Ring2::Writer::write(const void* const data, const size_t data_len)
{
    // empty records are not allowed
    if (data_len == 0)
        return false;

    // a guarding byte, writer should never move to the very end
    // (but reader can, which will empty the store)
    if (ptr + LEN_SIZE + data_len < end)
    {
        // normal case
        *(LEN_TYPE*)ptr = data_len;
        memcpy(ptr + LEN_SIZE, data, data_len);
        ptr += LEN_SIZE + data_len;
        return true;
    }
    else if (no_turns)
    {
        // overflow
        return false;
    }

    // wrapping case
    const auto zero_record = (ptr + LEN_SIZE <= end);
    const auto ptr_orig = ptr;
    const auto end_orig = end;

    no_turns = true;
    ptr = store.store;
    end = store.read_ptr.load(std::memory_order_acquire);

    auto res = ptr != end and write(data, data_len);

    if (res)
    {
        if (zero_record)
            *(LEN_TYPE*)ptr_orig = 0;
    }
    else
    {
        no_turns = false;
        ptr = ptr_orig;
        end = end_orig;
    }

    return res;
}

inline void Ring2::Writer::retry()
{
    *this = store.writer();
}

inline void Ring2::Writer::push()
{
    store.write_ptr.store(ptr, std::memory_order_release);
}

// cppcheck-suppress operatorEqVarError
inline Ring2::Writer& Ring2::Writer::operator =(Ring2::Writer&& other)
{
    ptr = other.ptr;
    end = other.end;
    no_turns = other.no_turns;

    return *this;
}

inline void* Ring2::Reader::read(size_t& data_len)
{
    data_len = 0;

    // next record size
    if (ptr + LEN_SIZE <= end)
        data_len = *(LEN_TYPE*)ptr;

    if (data_len != 0 and ptr + LEN_SIZE + data_len <= end)
    {
        // normal case
        ptr += LEN_SIZE;
        auto data = ptr;
        ptr += data_len;

        return data;
    }
    else if (more_turns)
    {
        // wrapping case
        more_turns = false;
        ptr = store.store;
        end = store.write_ptr.load(std::memory_order_acquire);

        return read(data_len);
    }

    // underflow
    assert(data_len == 0);
    return nullptr;
}

inline void Ring2::Reader::retry()
{
    *this = store.reader();
}

inline void Ring2::Reader::pop()
{
    store.read_ptr.store(ptr, std::memory_order_release);
}

// cppcheck-suppress operatorEqVarError
inline Ring2::Reader& Ring2::Reader::operator =(Ring2::Reader&& other)
{
    ptr = other.ptr;
    end = other.end;
    more_turns = other.more_turns;

    return *this;
}

#endif
