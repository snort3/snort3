/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// stream_splitter.h author Russ Combs <rucombs@cisco.com>
// for protocol aware flushing (PAF)

#ifndef TCP_SPLITTER_H
#define TCP_SPLITTER_H

#include "main/snort_types.h"
#include "main/thread.h"

class Flow;

enum PAF_Status // FIXIT move inside StreamSplitter
{
    PAF_ABORT,   // non-paf operation
    PAF_START,   // internal use only
    PAF_SEARCH,  // searching for next flush point
    PAF_FLUSH,   // flush at given offset
    PAF_SKIP     // skip ahead to given offset
};

struct StreamBuffer
{
    const uint8_t* data;
    unsigned length;
};

//-------------------------------------------------------------------------

class StreamSplitter
{
public:
    virtual ~StreamSplitter() { };

    virtual PAF_Status scan(
        Flow*,
        const uint8_t* data,   // in order segment data as it arrives
        uint32_t len,          // length of data
        uint32_t flags,        // packet flags indicating direction of data
        uint32_t* fp           // flush point (offset) relative to data
    ) = 0;

    virtual const StreamBuffer* reassemble(
        Flow*,
        unsigned total,        // total amount to flush (sum of iterations)
        unsigned offset,       // data offset from start of reassembly
        const uint8_t* data,   // data to reassemble
        unsigned len,          // length of data to process this iteration
        uint32_t flags,        // packet flags indicating pdu head and/or tail
        unsigned& copied       // actual data copied (1 <= copied <= len)
    );

    virtual bool is_paf() { return false; };
    virtual uint32_t max();

    virtual void reset() { };
    virtual void update() { };

    bool to_server() { return c2s; };
    bool to_client() { return !c2s; };

protected:
    StreamSplitter(bool b) { c2s = b; };

private:
    bool c2s;
};

//-------------------------------------------------------------------------
// accumulated tcp over maximum splitter (aka footprint)

class AtomSplitter : public StreamSplitter
{
public:
    AtomSplitter(bool, uint32_t size = 0);
    ~AtomSplitter();

    PAF_Status scan(
        Flow*,
        const uint8_t* data,
        uint32_t len,
        uint32_t flags,
        uint32_t* fp
    );
    void reset();
    void update();

private:
    uint16_t base;
    uint16_t min;
    uint16_t segs;
    uint16_t bytes;
};

#endif

