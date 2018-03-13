//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_splitter.h"

#include "detection/detection_engine.h"
#include "main/snort_config.h"
#include "protocols/packet.h"

#include "flush_bucket.h"
#include "stream.h"

using namespace snort;

unsigned StreamSplitter::max(Flow*)
{ return SnortConfig::get_conf()->max_pdu; }

uint16_t StreamSplitter::get_flush_bucket_size()
{ return FlushBucket::get_size(); }

const StreamBuffer StreamSplitter::reassemble(
    Flow*, unsigned, unsigned offset, const uint8_t* p,
    unsigned n, uint32_t flags, unsigned& copied)
{
    copied = n;
    if (n == 0)
        return { nullptr, 0 };

    unsigned max;
    uint8_t* pdu_buf = DetectionEngine::get_next_buffer(max);

    assert(offset + n < max);
    memcpy(pdu_buf+offset, p, n);

    if ( flags & PKT_PDU_TAIL )
        return { pdu_buf, offset + n };

    return { nullptr, 0 };
}

//--------------------------------------------------------------------------
// atom splitter
//--------------------------------------------------------------------------

AtomSplitter::AtomSplitter(bool b, uint16_t sz) : StreamSplitter(b)
{
    reset();
    base = sz;
    min = base + get_flush_bucket_size();
}

StreamSplitter::Status AtomSplitter::scan(
    Flow*, const uint8_t*, uint32_t len, uint32_t, uint32_t* fp)
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
    min = base + get_flush_bucket_size();
}

//--------------------------------------------------------------------------
// log splitter
//--------------------------------------------------------------------------

LogSplitter::LogSplitter(bool b) : StreamSplitter(b) { }

StreamSplitter::Status LogSplitter::scan(Flow*, const uint8_t*, uint32_t len, uint32_t,
    uint32_t* fp)
{
    *fp = len;
    return FLUSH;
}

//--------------------------------------------------------------------------
// stop-and-wait splitter
//--------------------------------------------------------------------------

StreamSplitter::Status StopAndWaitSplitter::scan(Flow* flow, const uint8_t*, uint32_t len,
    uint32_t, uint32_t*)
{
    StopAndWaitSplitter* peer = (StopAndWaitSplitter*)Stream::get_splitter(flow, !to_server());

    if ( peer and peer->saw_data() )
    {
        Packet* p = DetectionEngine::get_current_packet();

        if ( to_server() )
            Stream::flush_client(p);
        else
            Stream::flush_server(p);

        peer->reset();
    }
    byte_count += len;
    return StreamSplitter::SEARCH;
}
