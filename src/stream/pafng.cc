//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// pafng.cc author davis mcpherson davmcphe@cisco.com
// based on paf.cc author Russ Combs <rcombs@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pafng.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

using namespace snort;

//--------------------------------------------------------------------
// private state
//--------------------------------------------------------------------


#define PAF_LIMIT_FUZZ 1500

// 255 is max pseudo-random flush point; eth mtu ensures that maximum flushes
// are not trimmed which throws off the tracking total in stream5_paf.c
// max paf max = max datagram - eth mtu - 255 = 63780
#define MAX_PAF_MAX (65535 -  PAF_LIMIT_FUZZ - 255)

extern THREAD_LOCAL snort::ProfileStats pafPerfStats;

//--------------------------------------------------------------------

uint32_t ProtocolAwareFlusher::paf_flush (const PafAux& px, uint32_t* flags)
{
    uint32_t at = 0;
    *flags &= ~(PKT_PDU_HEAD | PKT_PDU_TAIL);

    switch ( px.ft )
    {
    case FT_NOP:
        return -1;

    case FT_SFP:
        *flags = 0;
        return -1;

    case FT_PAF:
        at = fpt;
        *flags |= PKT_PDU_TAIL;
        break;

    case FT_LIMIT:
        if (fpt > px.len)
        {
            at = px.len;
            fpt -= px.len;
        }
        else
        {
            at = fpt;
            fpt = px.len - fpt; // number of characters scanned but not flushing
        }
        break;

    // use of px.len is suboptimal here because the actual amount
    // flushed is determined later and can differ in certain cases
    // such as exceeding s5_pkt->max_dsize.  the actual amount
    // flushed would ideally be applied to fpt later.  for
    // now we try to circumvent such cases so we track correctly.
    //
    // FIXIT-L max_dsize should no longer be exceeded since it excludes headers.
    case FT_MAX:
        at = px.len;
        if ( fpt > px.len )
            fpt -= px.len;
        else
            fpt = 0;
        break;
    }

    if ( !at || !px.len )
        return -1;

    // safety - prevent seq + at < seq
    if ( at > 0x7FFFFFFF )
        at = 0x7FFFFFFF;

    if ( !tot )
        *flags |= PKT_PDU_HEAD;

    if ( *flags & PKT_PDU_TAIL )
        tot = 0;
    else
        tot += at;

    return at;
}

//--------------------------------------------------------------------

bool ProtocolAwareFlusher::paf_callback (PafAux& px, Packet* pkt, const uint8_t* data,
    uint32_t len, uint32_t flags)
{
    fpt = 0;
    state = splitter->scan(pkt, data, len, flags, &fpt);

    if ( state == StreamSplitter::ABORT || state == StreamSplitter::STOP )
        return false;

    if ( state != StreamSplitter::SEARCH )
    {
        fpt += px.idx;
        if ( fpt <= px.len )
        {
            px.idx = fpt;
            return true;
        }
    }
    px.idx = px.len;
    return false;
}

//--------------------------------------------------------------------

bool ProtocolAwareFlusher::paf_eval(PafAux& px, Packet* pkt, uint32_t flags,
    const uint8_t* data, uint32_t len)
{
    switch ( state )
    {
    case StreamSplitter::SEARCH:
        if ( px.len > px.idx )
            return paf_callback(px, pkt, data, len, flags);

        return false;

    case StreamSplitter::FLUSH:
        if ( px.len >= fpt )
        {
            px.ft = FT_PAF;
            state = StreamSplitter::SEARCH;
            return true;
        }
        if ( px.len >= splitter->max(pkt->flow) )
        {
            px.ft = FT_MAX;
            return false;
        }
        return false;

    case StreamSplitter::LIMIT:
        // if we are within PAF_LIMIT_FUZZ character of paf_max ...
        if ( px.len + PAF_LIMIT_FUZZ >= splitter->max(pkt->flow))
        {
            px.ft = FT_LIMIT;
            state = StreamSplitter::LIMITED;
            return false;
        }
        state = StreamSplitter::SEARCH;
        return false;

    case StreamSplitter::SKIP:
        if ( px.len > fpt )
        {
            if ( fpt > px.idx )
            {
                uint32_t delta = fpt - px.idx;
                if ( delta > len )
                    return false;

                data += delta;
                len -= delta;
            }
            px.idx = fpt;
            return paf_callback(px, pkt, data, len, flags);
        }
        return false;

    case StreamSplitter::LIMITED:
        // increment position by previously scanned bytes. set in paf_flush
        state = StreamSplitter::SEARCH;
        px.idx += fpt;
        fpt = 0;
        return true;

    default:
        // StreamSplitter::ABORT || StreamSplitter::START
        break;
    }

    px.ft = FT_SFP;
    return false;
}

//--------------------------------------------------------------------

int32_t ProtocolAwareFlusher::paf_check (Packet* pkt, const uint8_t* data, uint32_t len,
    uint32_t total, uint32_t seq, uint32_t* flags)
{
    Profile profile(pafPerfStats);  // cppcheck-suppress unreadVariable
    PafAux px;

    if ( !paf_initialized() )
    {
        seq_num = pos = seq;
        fpt = tot = 0;
        state = StreamSplitter::SEARCH;
    }
    else if ( SEQ_GT(seq, seq_num) )
    {
        // if seq jumped we have a gap.  Flush any queued data, then abort
        px.len = total - len;

        if ( px.len )
        {
            fpt = 0;
            px.ft = FT_MAX;
            state = StreamSplitter::ABORT;
            return paf_flush(px, flags);
        }
        *flags = 0;
        state = StreamSplitter::ABORT;
        return -1;
    }
    else if ( SEQ_LEQ(seq + len, seq_num) )
    {
        return -1;
    }
    else if ( SEQ_LT(seq, seq_num) )
    {
        uint32_t shift = seq_num - seq;
        data += shift;
        len -= shift;
    }

    seq_num += len;
    px.idx = total - len;

    // if 'total' is greater than the maximum paf_max AND 'total' is greater
    // than paf_max bytes (i.e. after we have finished analyzing the
    // current segment, total bytes analyzed will be greater than the
    // configured paf_max == splitter->max(), we must ensure a flush
    // occurs at the paf_max byte. So, we manually set the data's length and
    // total queued bytes (px.len) to guarantee that at most paf_max bytes will
    // be analyzed and flushed since the last flush point.  It should also be
    // noted that we perform the check here rather in in paf_flush() to
    // avoid scanning the same data twice. The first scan would analyze the
    // entire segment and the second scan would analyze this segments
    // unflushed data.
    if ( total >= MAX_PAF_MAX && total > splitter->max(pkt->flow) )
    {
        px.len = MAX_PAF_MAX;
        len = len + px.len - total;
    }
    else
        px.len = total;

    do
    {
        px.ft = FT_NOP;
        uint32_t idx = px.idx;

        const bool cont = paf_eval(px, pkt, *flags, data, len);

        if ( px.ft != FT_NOP )
        {
            int32_t fp = paf_flush(px, flags);
            paf_jump(fp);
            return fp;
        }

        if ( !cont )
            break;

        if ( px.idx > idx )
        {
            uint32_t shift = px.idx - idx;
            if ( shift > len )
                shift = len;
            data += shift;
            len -= shift;
        }
    }
    while ( true );

    if ( state == StreamSplitter::ABORT )
        *flags = 0;

    else if ( (state != StreamSplitter::FLUSH) && (px.len > splitter->max(pkt->flow)) )
    {
        px.ft = FT_MAX;
        uint32_t fp = paf_flush(px, flags);
        paf_jump(fp);
        return fp;
    }

    return -1;
}

