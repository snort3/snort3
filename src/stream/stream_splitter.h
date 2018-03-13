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
// stream_splitter.h author Russ Combs <rucombs@cisco.com>

#ifndef TCP_SPLITTER_H
#define TCP_SPLITTER_H

#include "main/snort_types.h"

namespace snort
{
class Flow;

struct StreamBuffer
{
    const uint8_t* data;
    unsigned length;
};

//-------------------------------------------------------------------------

class SO_PUBLIC StreamSplitter
{
public:
    virtual ~StreamSplitter() = default;

    enum Status
    {
        ABORT,  // non-paf operation
        START,  // internal use only
        SEARCH, // searching for next flush point
        FLUSH,  // flush at given offset
        LIMIT,  // flush to given offset upon reaching paf_max
        SKIP,   // skip ahead to given offset
        LIMITED // previously did limit flush
    };

    // scan(), finish(), reassemble() are called in this order:
    // (scan (reassemble)*)* finish (reassemble)*

    virtual Status scan(
        Flow*,
        const uint8_t* data,   // in order segment data as it arrives
        uint32_t len,          // length of data
        uint32_t flags,        // packet flags indicating direction of data
        uint32_t* fp           // flush point (offset) relative to data
        ) = 0;

    // finish indicates end of scanning
    // return false to discard any unflushed data
    virtual bool finish(Flow*) { return true; }

    // the last call to reassemble() will be made with len == 0 if
    // finish() returned true as an opportunity for a final flush
    virtual const StreamBuffer reassemble(
        Flow*,
        unsigned total,        // total amount to flush (sum of iterations)
        unsigned offset,       // data offset from start of reassembly
        const uint8_t* data,   // data to reassemble
        unsigned len,          // length of data to process this iteration
        uint32_t flags,        // packet flags indicating pdu head and/or tail
        unsigned& copied       // actual data copied (1 <= copied <= len)
        );

    virtual bool is_paf() { return false; }
    virtual unsigned max(Flow*);

    // FIXIT-L reset is not currently used and may not be needed at all.
    //         determine if this is so and remove if possible
    virtual void reset() { }
    virtual void update() { }

    unsigned get_max_pdu() { return max_pdu; }
    bool to_server() { return c2s; }
    bool to_client() { return !c2s; }

protected:
    StreamSplitter(bool b) : c2s(b) { }
    uint16_t get_flush_bucket_size();

private:
    const bool c2s;
    const unsigned max_pdu = 65536;
};

//-------------------------------------------------------------------------
// accumulated tcp over maximum splitter (aka footprint)

class AtomSplitter : public StreamSplitter
{
public:
    AtomSplitter(bool, uint16_t size = 0);

    Status scan(Flow*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override;
    void reset() override;
    void update() override;

private:
    uint16_t base;
    uint16_t min;
    uint16_t segs;
    uint16_t bytes;
};

//-------------------------------------------------------------------------
// length of given segment splitter (pass-thru)

class LogSplitter : public StreamSplitter
{
public:
    LogSplitter(bool);

    Status scan(Flow*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override;
};

//-------------------------------------------------------------------------
// stop-and-wait splitter (flush opposite direction upon data)

class StopAndWaitSplitter : public StreamSplitter
{
public:
    StopAndWaitSplitter(bool b) : StreamSplitter(b) { }

    Status scan(Flow*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override;

    bool saw_data()
    { return byte_count > 0; }

    void reset() override
    { byte_count = 0; }

private:
    unsigned byte_count = 0;
};
}
#endif

