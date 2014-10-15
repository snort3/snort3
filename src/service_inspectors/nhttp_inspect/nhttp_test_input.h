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

#include "nhttp_enum.h"
#include "nhttp_flow_data.h"

class NHttpTestInput {
public:
    NHttpTestInput(const char *fileName);
    ~NHttpTestInput();
    void scan(uint8_t*& data, uint32_t& length, NHttpEnums::SourceId& source_id, bool& tcp_close, bool& need_break);
    void flush(uint32_t length);
    void reassemble(uint8_t** buffer, unsigned& length, NHttpEnums::SourceId source_id, const NHttpFlowData* session_data,
       bool& tcp_close);

private:
    FILE* test_data_file;
    uint8_t msg_buf[2 * NHttpEnums::MAXOCTETS];
    bool flushed = false;
    NHttpEnums::SourceId last_source_id = NHttpEnums::SRC_CLIENT;   // current direction of traffic flow. Toggled by commands in file.
    bool just_flushed = true;   // all octets sent to inspection and must resume reading the file
    bool tcp_closed = false;  // so we can keep presenting a TCP close to PAF until all the remaining octets are consumed and flushed
    uint32_t flush_octets = 0;  // number of octets that have been flushed and must go to inspection
    uint32_t previous_offset = 0;   // last character in the buffer shown to PAF but not flushed yet
    uint32_t end_offset = 0;   // last read character in the buffer
};

#endif

