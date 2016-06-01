//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// stream_splitter.cc author Russ Combs <rucombs@cisco.com>

#include "stream_splitter.h"

#include <assert.h>
#include <string.h>

#include "flush_bucket.h"
#include "protocols/packet.h"

static THREAD_LOCAL uint8_t pdu_buf[65536];
static THREAD_LOCAL StreamBuffer str_buf;

unsigned StreamSplitter::max_pdu = 16384;

void StreamSplitter::set_max(unsigned m)
{ max_pdu = m; }

unsigned StreamSplitter::max(Flow*)
{ return max_pdu; }

const StreamBuffer* StreamSplitter::reassemble(
    Flow*, unsigned, unsigned offset, const uint8_t* p,
    unsigned n, uint32_t flags, unsigned& copied)
{
    assert(offset + n < sizeof(pdu_buf));
    memcpy(pdu_buf+offset, p, n);
    copied = n;

    if ( flags & PKT_PDU_TAIL )
    {
        str_buf.data = pdu_buf;
        str_buf.length = offset + n;
        return &str_buf;
    }
    return nullptr;
}

//--------------------------------------------------------------------------
// atom splitter
//--------------------------------------------------------------------------

AtomSplitter::AtomSplitter(bool b, uint32_t sz) : StreamSplitter(b)
{
    reset();
    base = sz;
    min = base + FlushBucket::get_size();
}

AtomSplitter::~AtomSplitter() { }

StreamSplitter::Status AtomSplitter::scan(
    Flow*, const uint8_t*, uint32_t len, uint32_t, uint32_t* fp
    )
{
    bytes += len;
    segs++;

    if ( segs >= 2 && bytes >= min )
    {
        *fp = len;
        return FLUSH;
    }
    return SEARCH;
}

void AtomSplitter::reset()
{
    bytes = segs = 0;
}

void AtomSplitter::update()
{
    reset();
    min = base + FlushBucket::get_size();
}

#if 0
static inline int CheckFlushCoercion(  // FIXIT-M this should be part of a new splitter
    Packet* p, FlushMgr* fm, uint16_t flush_factor
    )
{
    if ( !flush_factor )
        return 0;

    if (
        p->dsize &&
        (p->dsize < fm->last_size) &&
        (fm->last_count >= flush_factor) )
    {
        fm->last_size = 0;
        fm->last_count = 0;
        return 1;
    }
    if ( p->dsize > fm->last_size )
        fm->last_size = p->dsize;

    fm->last_count++;
    return 0;
}

#endif

//--------------------------------------------------------------------------
// log splitter
//--------------------------------------------------------------------------

LogSplitter::LogSplitter(bool b) : StreamSplitter(b) { }

StreamSplitter::Status LogSplitter::scan(
    Flow*, const uint8_t*, uint32_t len, uint32_t, uint32_t* fp
    )
{
    *fp = len;
    return FLUSH;
}

