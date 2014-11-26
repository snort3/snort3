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
// nhttp_test_input.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_TEST_INPUT_H
#define NHTTP_TEST_INPUT_H

#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_flow_data.h"

class NHttpTestInput {
public:
    NHttpTestInput(const char *fileName);
    ~NHttpTestInput();
    void scan(uint8_t*& data, uint32_t& length, NHttpEnums::SourceId source_id, bool& tcp_close, bool& need_break);
    void flush(uint32_t length);
    void reassemble(uint8_t** buffer, unsigned& length, NHttpEnums::SourceId source_id, const NHttpFlowData* session_data,
       bool& tcp_close);

private:
    FILE* test_data_file;
    uint8_t msg_buf[2 * NHttpEnums::MAXOCTETS];

    // data has been flushed and must be sent by reassemble() before more data may be given to scan()
    bool flushed = false;

    // current direction of traffic flow. Toggled by commands in file.
    NHttpEnums::SourceId last_source_id = NHttpEnums::SRC_CLIENT;

    // reassemble just completed and all flushed octets forwarded, time to resume scan()
    bool just_flushed = true;

    // TCP connection directional close at end of current paragraph
    bool tcp_closed = false;

    // number of octets that have been flushed and must be sent by reassemble
    uint32_t flush_octets = 0;

    // last character in the buffer previously shown to PAF but not flushed yet
    uint32_t previous_offset = 0;

    // last read character in the buffer
    uint32_t end_offset = 0;
};

#endif

