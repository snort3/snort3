//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_splitter.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_SPLITTER_H
#define NHTTP_SPLITTER_H

#include <assert.h>

#include "nhttp_enum.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"

//-------------------------------------------------------------------------
// NHttpSplitter class
//-------------------------------------------------------------------------

class NHttpSplitter
{
public:
    virtual ~NHttpSplitter() = default;
    virtual NHttpEnums::ScanResult split(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events) = 0;
    uint32_t get_num_flush() const { return num_flush; }
    uint32_t get_octets_seen() const { return octets_seen; }
    virtual uint32_t get_num_excess() const { return 0; }
    virtual uint32_t get_num_head_lines() const { return 0; }

protected:
    // number of octets processed by previous split() calls that returned NOTFOUND
    uint32_t octets_seen = 0;

    uint32_t num_crlf = 0;
    uint32_t num_flush = 0;
};

class NHttpStartSplitter : public NHttpSplitter
{
public:
    NHttpEnums::ScanResult split(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events) override;
    uint32_t get_num_excess() const override { return (num_flush > 0) ? num_crlf : 0; }

private:
    static const int MAX_LEADING_WHITESPACE = 20;
};

class NHttpHeaderSplitter : public NHttpSplitter
{
public:
    NHttpEnums::ScanResult split(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events) override;
    uint32_t get_num_excess() const override { return (num_flush > 0) ? num_crlf : 0; }
    uint32_t get_num_head_lines() const override { return num_head_lines; }

private:
    unsigned first_lf = 0;
    int32_t num_head_lines = 0;
};

class NHttpBodySplitter : public NHttpSplitter
{
public:
    explicit NHttpBodySplitter(int64_t expected_length) : remaining(expected_length)
        { assert(remaining > 0); }
    NHttpEnums::ScanResult split(const uint8_t*, uint32_t, NHttpInfractions&, NHttpEventGen&)
        override;

private:
    int64_t remaining;
};

class NHttpChunkSplitter : public NHttpSplitter
{
public:
    NHttpEnums::ScanResult split(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events) override;

private:
    uint32_t data_seen = 0;
    NHttpEnums::ChunkState curr_state = NHttpEnums::CHUNK_ZEROS;
    uint32_t expected = 0;
    uint32_t num_zeros = 0;
    uint32_t digits_seen = 0;
    bool new_section = false;
};

#endif

