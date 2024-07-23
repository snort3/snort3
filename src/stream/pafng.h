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

//--------------------------------------------------------------------
// protocol aware flushing stuff
// pafng.h author davis mcpherson davmcphe@cisco.com
//--------------------------------------------------------------------

#ifndef PAFNG_H
#define PAFNG_H

#include "main/snort_types.h"
#include "main/thread.h"
#include "profiler/profiler_defs.h"
#include "stream/stream_splitter.h"

namespace snort
{
struct Packet;
}

enum FlushType
{
    FT_NOP,  // no flush
    FT_SFP,  // abort paf
    FT_PAF,  // flush to paf pt when len >= paf
    FT_LIMIT,  // flush to paf pt, don't update flags
    FT_MAX   // flush len when len >= max
};

struct PafAux
{
    FlushType ft;
    uint32_t len;  // total bytes queued
    uint32_t idx;  // offset from start of queued bytes
};

class  ProtocolAwareFlusher
{
public:
    ProtocolAwareFlusher() { }
    ~ProtocolAwareFlusher() { }

    SO_PUBLIC void paf_setup(snort::StreamSplitter* ss)
    {
        splitter = ss;
        state = snort::StreamSplitter::START;
    }

    void paf_reset ()
    { state = snort::StreamSplitter::START; }

    void paf_clear ()
    { state = snort::StreamSplitter::ABORT; }

    uint32_t paf_position ()
    { return seq_num; }

    SO_PUBLIC uint32_t paf_initialized ()
    { return ( state != snort::StreamSplitter::START ); }

    SO_PUBLIC void paf_initialize(uint32_t seq)
    {
        seq_num = pos = seq;
        fpt = tot = 0;
        state = snort::StreamSplitter::SEARCH;
    }

    uint32_t paf_active ()
    { return ( state != snort::StreamSplitter::ABORT ); }

    void paf_jump(uint32_t n)
    {
        pos += n;
        seq_num = pos;
    }

    // called on each in order segment
    SO_PUBLIC int32_t paf_check(snort::Packet* p, const uint8_t* data, uint32_t len,
        uint32_t total, uint32_t seqnum, uint32_t* flags);

    uint32_t seq_num = 0;    // stream cursor
    uint32_t pos = 0;    // last flush position
    uint32_t fpt = 0;    // current flush point
    uint32_t tot = 0;    // total bytes flushed
    snort::StreamSplitter::Status state = snort::StreamSplitter::START;  // current scan state

private:
    uint32_t paf_flush (const PafAux& px, uint32_t* flags);
    bool paf_callback (PafAux&, snort::Packet*, const uint8_t* data, uint32_t len, uint32_t flags);
    bool paf_eval (PafAux&, snort::Packet*, uint32_t flags, const uint8_t* data, uint32_t len);

    snort::StreamSplitter* splitter = nullptr;
};

#endif

