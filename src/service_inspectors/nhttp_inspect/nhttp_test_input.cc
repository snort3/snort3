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
//  @brief      Interface to file of test messages
//


#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdexcept>
#include <stdint.h>

#include "nhttp_test_manager.h"
#include "nhttp_test_input.h"

using namespace NHttpEnums;

NHttpTestInput::NHttpTestInput(const char *file_name) {
    if ((test_data_file = fopen(file_name, "r")) == nullptr) throw std::runtime_error("Cannot open test input file");
}

NHttpTestInput::~NHttpTestInput() {
    fclose(test_data_file);
}

// Read from the test data file and present to PAF.
// In the process we may need to skip comments, execute simple commands, and handle escape sequences.
// The best way to understand this function is to read the comments at the top of the file of test cases.
void NHttpTestInput::scan(uint8_t*& data, uint32_t &length, SourceId &source_id, bool &tcp_close, bool &need_break) {
    source_id = last_source_id;
    tcp_close = false;
    need_break = false;

    // Need to create and inspect additional message section(s) from the previous flush before we read new stuff
    if ((end_offset == 0) && (flush_octets > 0)) {
        length = 0;
        return;
    }

    if (just_flushed) {
        // PAF just flushed and it has all been sent to inspection. There may or may not be leftover data from the
        // last segment that was not flushed.
        just_flushed = false;
        data = msg_buf;
        length = end_offset - flush_octets;  // this is the leftover data
        previous_offset = 0;
        end_offset = length;
        if (length > 0) {
            // Must present unflushed leftovers to PAF again.
            // If we don't take this opportunity to left justify our data in the buffer we may "walk" to the right until we run out of buffer space
            memmove(msg_buf, msg_buf+flush_octets, length);
            tcp_close = tcp_closed;
            flush_octets = 0;
            return;
        }
        // If we reach here then PAF has already flushed all the data we have read so far.
        tcp_closed = false;
        flush_octets = 0;
    }
    else {
        // The data we gave PAF last time was not flushed
        length = 0;
        previous_offset = end_offset;
        data = msg_buf + previous_offset;
    }

    // Now we need to move forward by reading more data from the file
    int new_char;
    typedef enum { WAITING, COMMENT, COMMAND, SECTION, ESCAPE, HEXVAL } State;
    State state = WAITING;
    bool ending;
    int command_length;
    const int max_command = 100;
    char command_value[max_command];
    uint8_t hex_val;
    int num_digits;

    while ((new_char = getc(test_data_file)) != EOF) {
        switch (state) {
          case WAITING:
            if (new_char == '#') {
                state = COMMENT;
            }
            else if (new_char == '@') {
                state = COMMAND;
                command_length = 0;
            }
            else if (new_char == '\\') {
                state = ESCAPE;
                ending = false;
            }
            else if (new_char != '\n') {
                state = SECTION;
                ending = false;
                data[length++] = (uint8_t) new_char;
            }
            break;
          case COMMENT:
            if (new_char == '\n') {
                state = WAITING;
            }
            break;
          case COMMAND:
            if (new_char == '\n') {
                state = WAITING;
                if ((command_length == strlen("request")) && !memcmp(command_value, "request", strlen("request"))) {
                    source_id = last_source_id = SRC_CLIENT;
                }
                else if ((command_length == strlen("response")) && !memcmp(command_value, "response", strlen("response"))) {
                    source_id = last_source_id = SRC_SERVER;
                }
                else if ((command_length == strlen("break")) && !memcmp(command_value, "break", strlen("break"))) {
                    need_break = true;
                }
                else if ((command_length == strlen("tcpclose")) && !memcmp(command_value, "tcpclose", strlen("tcpclose"))) {
                    tcp_close = true;
                    tcp_closed = true;
                }
                else if (command_length > 0) {
                    // Look for a test number
                    bool is_number = true;
                    for (int k=0; (k < command_length) && is_number; k++) {
                        is_number = (command_value[k] >= '0') && (command_value[k] <= '9');
                    }
                    if (is_number) {
                        int64_t test_number = 0;
                        for (int j=0; j < command_length; j++) {
                            test_number = test_number * 10 + (command_value[j] - '0');
                        }
                        NHttpTestManager::update_test_number(test_number);
                    }
                    else {
                        // Bad command in test file
                        assert(0);
                    }
                }
            }
            else {
                if (command_length < max_command) {
                     command_value[command_length++] = new_char;
                }
                else {
                    assert(0);
                }
            }
            break;
          case SECTION:
            if (new_char == '\\') {
                state = ESCAPE;
                ending = false;
            }
            else if (new_char == '\n') {
                if (ending) {
                    // Found the blank line that ends the section.
                    end_offset = previous_offset + length;
                    return;
                }
                ending = true;
            }
            else {
                ending = false;
                data[length++] = (uint8_t) new_char;
            }
            break;
          case ESCAPE:
            switch (new_char) {
              case 'n':  state = SECTION; data[length++] = '\n'; break;
              case 'r':  state = SECTION; data[length++] = '\r'; break;
              case 't':  state = SECTION; data[length++] = '\t'; break;
              case '#':  state = SECTION; data[length++] = '#';  break;
              case '@':  state = SECTION; data[length++] = '@';  break;
              case '\\': state = SECTION; data[length++] = '\\'; break;
              case 'x':
              case 'X':  state = HEXVAL; hex_val = 0; num_digits = 0; break;
              default:   assert(0); state = SECTION; break;
            }
            break;
          case HEXVAL:
            if ((new_char >= '0') && (new_char <= '9')) hex_val = hex_val * 16 + (new_char - '0');
            else if ((new_char >= 'a') && (new_char <= 'f')) hex_val = hex_val * 16 + 10 + (new_char - 'a');
            else if ((new_char >= 'A') && (new_char <= 'F')) hex_val = hex_val * 16 + 10 + (new_char - 'A');
            else assert(0);
            if (++num_digits == 2) {
                data[length++] = hex_val;
                state = SECTION;
            }
            break;
        }
        // Don't allow a buffer overrun.
        if (previous_offset + length >= sizeof(msg_buf)) assert(0);
    }
    // End-of-file. Return everything we have so far.
    end_offset = previous_offset + length;
    return;
}

void NHttpTestInput::flush(uint32_t length) {
    flush_octets = previous_offset + length;
    just_flushed = true;
}


void NHttpTestInput::reassemble(uint8_t **buffer, unsigned &length, SourceId &source_id, NHttpFlowData* session_data) {
    source_id = last_source_id;
    *buffer = msg_buf;

    if (flush_octets <= end_offset) {
        // All the data we need comes from the file
        length = flush_octets;
    }
    else {
        // We need to generate additional data to fill out the body or chunk section. We may come through here
        // multiple times as we generate all the maximum size body sections needed for a single flush.
        uint32_t paf_max = 16384 - session_data->chunk_buffer_length[source_id];
        length = (flush_octets <= paf_max) ? flush_octets : paf_max;
        for (uint32_t k = end_offset; k < length; k++) {
            msg_buf[k] = 'A' + k % 26;
        }
        flush_octets -= length;
        end_offset = 0;
    }
}


