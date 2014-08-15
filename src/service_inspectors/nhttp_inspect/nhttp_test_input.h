/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      Read test file and present test input to PAF
//

#ifndef NHTTP_TEST_INPUT_H
#define NHTTP_TEST_INPUT_H

class NHttpTestInput {
public:
    NHttpTestInput(const char *fileName);
    ~NHttpTestInput();
    void scan(uint8_t*& data, uint32_t &length, NHttpEnums::SourceId &source_id, bool &tcp_close, bool &need_break);
    void flush(uint32_t length);
    void reassemble(uint8_t **buffer, unsigned &length, NHttpEnums::SourceId &source_id);

    static bool test_input;
    static NHttpTestInput *test_input_source;
    int64_t get_test_number() { return test_number; };
private:
    FILE *test_data_file;
    uint8_t msg_buf[2 * NHttpEnums::MAXOCTETS];
    bool just_flushed = true;   // all octets sent to inspection and must resume reading the file
    bool tcp_already_closed = false;  // so we can keep presenting a TCP close to PAF until all the remaining octets are consumed and flushed
    uint32_t flush_octets = 0;  // number of octets that have been flushed and must go to inspection
    uint32_t previous_offset = 0;   // last character in the buffer shown to PAF but not flushed yet
    uint32_t end_offset = 0;   // last read character in the buffer
    int64_t test_number = 0;   // for numbering test output files
    NHttpEnums::SourceId last_source_id = NHttpEnums::SRC_CLIENT;   // current direction of traffic flow. Toggled by commands in file.
    uint8_t term_bytes[2] = { 'x', 'y' };
};

#endif

