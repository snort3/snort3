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
// nhttp_cutter.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_CUTTER_H
#define NHTTP_CUTTER_H

#include <assert.h>

#include "nhttp_enum.h"
#include "nhttp_infractions.h"
#include "nhttp_event_gen.h"

//-------------------------------------------------------------------------
// NHttpCutter class and subclasses
//-------------------------------------------------------------------------

class NHttpCutter
{
public:
    virtual ~NHttpCutter() = default;
    virtual NHttpEnums::ScanResult cut(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events, uint32_t flow_target,
        uint32_t flow_max) = 0;
    uint32_t get_num_flush() const { return num_flush; }
    uint32_t get_octets_seen() const { return octets_seen; }
    virtual uint32_t get_num_excess() const { return 0; }
    virtual uint32_t get_num_head_lines() const { return 0; }
    virtual bool get_is_broken_chunk() const { return false; }
    virtual uint32_t get_num_good_chunks() const { return 0; }

protected:
    // number of octets processed by previous cut() calls that returned NOTFOUND
    uint32_t octets_seen = 0;
    uint32_t num_crlf = 0;
    uint32_t num_flush = 0;
};

class NHttpStartCutter : public NHttpCutter
{
public:
    NHttpEnums::ScanResult cut(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events, uint32_t, uint32_t) override;
    uint32_t get_num_excess() const override { return (num_flush > 0) ? num_crlf : 0; }

protected:
    enum ValidationResult { V_GOOD, V_BAD, V_TBD };

private:
    static const int MAX_LEADING_WHITESPACE = 20;
    virtual ValidationResult validate(uint8_t octet) = 0;
    bool validated = false;
};

class NHttpRequestCutter : public NHttpStartCutter
{
private:
    uint32_t octets_checked = 0;
    ValidationResult validate(uint8_t octet) override;
};

class NHttpStatusCutter : public NHttpStartCutter
{
private:
    uint32_t octets_checked = 0;
    ValidationResult validate(uint8_t octet) override;
};

class NHttpHeaderCutter : public NHttpCutter
{
public:
    NHttpEnums::ScanResult cut(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events, uint32_t, uint32_t) override;
    uint32_t get_num_excess() const override { return (num_flush > 0) ? num_crlf : 0; }
    uint32_t get_num_head_lines() const override { return num_head_lines; }

private:
    unsigned first_lf = 0;
    int32_t num_head_lines = 0;
};

class NHttpBodyClCutter : public NHttpCutter
{
public:
    explicit NHttpBodyClCutter(int64_t expected_length) : remaining(expected_length)
        { assert(remaining > 0); }
    NHttpEnums::ScanResult cut(const uint8_t*, uint32_t length, NHttpInfractions&, NHttpEventGen&,
        uint32_t flow_target, uint32_t flow_max) override;

private:
    int64_t remaining;
};

class NHttpBodyOldCutter : public NHttpCutter
{
public:
    NHttpEnums::ScanResult cut(const uint8_t*, uint32_t, NHttpInfractions&, NHttpEventGen&,
        uint32_t flow_target, uint32_t) override;
};

class NHttpBodyChunkCutter : public NHttpCutter
{
public:
    NHttpEnums::ScanResult cut(const uint8_t* buffer, uint32_t length,
        NHttpInfractions& infractions, NHttpEventGen& events, uint32_t flow_target, uint32_t)
        override;
    bool get_is_broken_chunk() const override { return curr_state == NHttpEnums::CHUNK_BAD; }
    uint32_t get_num_good_chunks() const override { return num_good_chunks; }

private:
    uint32_t data_seen = 0;
    NHttpEnums::ChunkState curr_state = NHttpEnums::CHUNK_ZEROS;
    uint32_t expected = 0;
    uint32_t num_zeros = 0;
    uint32_t digits_seen = 0;
    bool new_section = false;
    uint32_t num_good_chunks = 0;  // that end in the current section
};

#endif

