//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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

// ber_mock.h author Oleksandr Stepanov <ostepano@cisco.com>

#ifndef BER_MOCK_H
#define BER_MOCK_H

#include "helpers/ber.h"

struct BerMockResult
{
    bool result;
    snort::BerElement element;
};

// fixed-capacity FIFO of results BerReader::read() hands back, in order.
class BerMockQueue
{
public:
    void reset()
    { head = count = 0; }

    void push(const BerMockResult& r)
    {
        if ( count < CAPACITY )
            items[(head + count++) % CAPACITY] = r;
    }

    bool empty() const
    { return count == 0; }

    BerMockResult pop()
    {
        const BerMockResult r = items[head];
        head = (head + 1) % CAPACITY;
        --count;
        return r;
    }

private:
    static const unsigned CAPACITY = 16;
    BerMockResult items[CAPACITY] = {};
    unsigned head = 0;
    unsigned count = 0;
};

inline BerMockQueue& ber_mock_queue()
{
    static BerMockQueue queue;
    return queue;
}

// queue one BerReader::read() result. header_length drives how far the decoders
// advance the cursor for BER_TAG__ADD_HEADER_ONLY / ADD_HEADER_AND_PAYLOAD.
inline void ber_mock_push(uint32_t type, uint32_t length = 0,
    uint64_t header_length = 2, bool result = true, const uint8_t* data = nullptr)
{
    BerMockResult r;
    r.result = result;
    r.element.type = type;
    r.element.length = length;
    r.element.header_length = header_length;
    r.element.total_length = header_length + length;
    r.element.data = data;
    ber_mock_queue().push(r);
}

// drop any programmed results; call from a test group setup()/teardown()
inline void ber_mock_reset()
{
    ber_mock_queue().reset();
}

namespace snort
{

inline bool BerReader::read(const uint8_t* c, BerElement& e)
{
    BerMockQueue& queue = ber_mock_queue();

    if ( queue.empty() )
        return false;

    const BerMockResult r = queue.pop();

    e = r.element;

    // same bound as the production reader
    if ( e.total_length > UINT32_MAX - (uint64_t)(c - beg) )
        return false;

    return r.result;
}

}

#endif
