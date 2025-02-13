//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_test_input.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_TEST_INPUT_H
#define HTTP_TEST_INPUT_H

#ifdef REG_TEST

#include <cstdio>
#include <queue>

#include "http_common.h"
#include "http_enum.h"
#include "http_flow_data.h"

class HttpTestInput
{
public:
    HttpTestInput(const char* fileName);
    ~HttpTestInput();
    void scan(uint8_t*& data, uint32_t& length, HttpCommon::SourceId source_id, uint64_t seq_num);
    void flush(uint32_t num_octets);
    void reassemble(uint8_t** buffer, unsigned& length, unsigned& total, unsigned& offset,
        uint32_t& flags, HttpCommon::SourceId source_id, bool& tcp_close);
    bool finish();

private:
    FILE* test_data_file;
    // FIXIT-E Figure out how big this buf needs to be and revise value
    uint8_t msg_buf[2][2 * HttpEnums::MAX_OCTETS] = {{0}, {0}};
    std::queue<uint32_t> segments[2];
    FILE* include_file[2] = { nullptr, nullptr };

    // break command has been read and we are waiting for a new underlying flow to start
    bool need_break = false;

    // Sequence number of the underlying flow we are currently piggybacking on
    uint64_t curr_seq_num = 0;

    // data has been flushed and must be sent by reassemble() before more data may be given to
    // scan()
    bool flushed = false;

    // current direction of traffic flow. Toggled by commands in file.
    HttpCommon::SourceId last_source_id = HttpCommon::SRC_CLIENT;

    // reassemble() just completed and all flushed octets forwarded, time to resume scan()
    bool just_flushed = false;

    // TCP connection directional close
    bool tcp_closed = false;

    // number of octets that have been flushed and must be sent by reassemble
    uint32_t flush_octets = 0;

    // Number of octets sent in previous calls to reassemble()
    uint32_t reassembled_octets = 0;

    // number of characters in the buffer previously shown to splitter but not flushed yet
    uint32_t previous_offset[2] = { 0, 0 };

    // number of characters in the buffer
    uint32_t end_offset[2] = { 0, 0 };

    void generate_h2_frame_header(const char command_value[], const unsigned command_length);

    void reset();
};

#endif
#endif

