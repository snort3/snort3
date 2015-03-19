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
// nhttp_test_input.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <stdexcept>

#include "nhttp_test_manager.h"
#include "nhttp_test_input.h"

using namespace NHttpEnums;

NHttpTestInput::NHttpTestInput(const char* file_name)
{
    if ((test_data_file = fopen(file_name, "r")) == nullptr)
        throw std::runtime_error("Cannot open test input file");
}

NHttpTestInput::~NHttpTestInput()
{
    fclose(test_data_file);
}

// Read from the test data file and present to StreamSplitter.
// In the process we may need to skip comments, execute simple commands, and handle escape
// sequences.
// The best way to understand this function is to read the comments at the top of the file of test
// cases.
void NHttpTestInput::scan(uint8_t*& data, uint32_t& length, SourceId source_id, bool& tcp_close,
    bool& need_break)
{
    need_break = false;
    // Don't proceed if we have previously flushed data not reassembled yet.
    // Piggyback on traffic moving in the correct direction.
    if (flushed || (source_id != last_source_id))
    {
        length = 0;
        return;
    }
    tcp_close = tcp_closed;

    if (just_flushed)
    {
        // StreamSplitter just flushed and it has all been sent by reassemble. There may or may not
        // be leftover data
        // from the last paragraph that was not flushed.
        just_flushed = false;
        data = msg_buf;
        length = end_offset - flush_octets;  // this is the leftover data
        previous_offset = 0;
        end_offset = length;
        if (length > 0)
        {
            // Must present unflushed leftovers to StreamSplitter again. If we don't take this
            // opportunity to left
            // justify our data in the buffer we may "walk" to the right until we run out of buffer
            // space.
            memmove(msg_buf, msg_buf+flush_octets, length);
            flush_octets = 0;
            return;
        }
        // If we reach here then StreamSplitter has already flushed all the data we have read so
        // far.
        tcp_closed = false;
        tcp_close = tcp_closed;
        flush_octets = 0;
    }
    else
    {
        // The data we gave StreamSplitter last time was not flushed
        length = 0;
        previous_offset = end_offset;
        data = msg_buf + previous_offset;
    }

    // Now we need to move forward by reading more data from the file
    int new_char;
    typedef enum { WAITING, COMMENT, COMMAND, PARAGRAPH, ESCAPE, HEXVAL } State;
    State state = WAITING;
    bool ending = false;
    int command_length = 0;
    const int max_command = 100;
    char command_value[max_command];
    uint8_t hex_val = 0;
    int num_digits = 0;

    while ((new_char = getc(test_data_file)) != EOF)
    {
        switch (state)
        {
        case WAITING:
            if (new_char == '#')
            {
                state = COMMENT;
            }
            else if (new_char == '@')
            {
                state = COMMAND;
                command_length = 0;
            }
            else if (new_char == '\\')
            {
                state = ESCAPE;
                ending = false;
            }
            else if (new_char != '\n')
            {
                state = PARAGRAPH;
                ending = false;
                data[length++] = (uint8_t)new_char;
            }
            break;
        case COMMENT:
            if (new_char == '\n')
            {
                state = WAITING;
            }
            break;
        case COMMAND:
            if (new_char == '\n')
            {
                state = WAITING;
                // FIXIT-L should not change direction with unflushed data remaining from previous
                // paragraph. At the
                // minimum need to test for this and assert.
                if ((command_length == strlen("request")) && !memcmp(command_value, "request",
                    strlen("request")))
                {
                    last_source_id = SRC_CLIENT;
                    if (source_id != last_source_id)
                    {
                        length = 0;
                        return;
                    }
                }
                else if ((command_length == strlen("response")) && !memcmp(command_value,
                    "response", strlen("response")))
                {
                    last_source_id = SRC_SERVER;
                    if (source_id != last_source_id)
                    {
                        length = 0;
                        return;
                    }
                }
                else if ((command_length == strlen("break")) && !memcmp(command_value, "break",
                    strlen("break")))
                {
                    need_break = true;
                }
                else if ((command_length == strlen("tcpclose")) && !memcmp(command_value,
                    "tcpclose", strlen("tcpclose")))
                {
                    tcp_closed = true;
                    tcp_close = tcp_closed;
                }
                else if (command_length > 0)
                {
                    // Look for a test number
                    bool is_number = true;
                    for (int k=0; (k < command_length) && is_number; k++)
                    {
                        is_number = (command_value[k] >= '0') && (command_value[k] <= '9');
                    }
                    if (is_number)
                    {
                        int64_t test_number = 0;
                        for (int j=0; j < command_length; j++)
                        {
                            test_number = test_number * 10 + (command_value[j] - '0');
                        }
                        NHttpTestManager::update_test_number(test_number);
                    }
                    else
                    {
                        // Bad command in test file
                        assert(0);
                    }
                }
            }
            else
            {
                if (command_length < max_command)
                {
                    command_value[command_length++] = new_char;
                }
                else
                {
                    assert(0);
                }
            }
            break;
        case PARAGRAPH:
            if (new_char == '\\')
            {
                state = ESCAPE;
                ending = false;
            }
            else if (new_char == '\n')
            {
                if (ending)
                {
                    // Found the second consecutive blank line that ends the paragraph.
                    end_offset = previous_offset + length;
                    return;
                }
                ending = true;
            }
            else
            {
                ending = false;
                data[length++] = (uint8_t)new_char;
            }
            break;
        case ESCAPE:
            switch (new_char)
            {
            case 'n':  state = PARAGRAPH; data[length++] = '\n'; break;
            case 'r':  state = PARAGRAPH; data[length++] = '\r'; break;
            case 't':  state = PARAGRAPH; data[length++] = '\t'; break;
            case '#':  state = PARAGRAPH; data[length++] = '#';  break;
            case '@':  state = PARAGRAPH; data[length++] = '@';  break;
            case '\\': state = PARAGRAPH; data[length++] = '\\'; break;
            case 'x':
            case 'X':  state = HEXVAL; hex_val = 0; num_digits = 0; break;
            default:   assert(0); state = PARAGRAPH; break;
            }
            break;
        case HEXVAL:
            if ((new_char >= '0') && (new_char <= '9'))
                hex_val = hex_val * 16 + (new_char - '0');
            else if ((new_char >= 'a') && (new_char <= 'f'))
                hex_val = hex_val * 16 + 10 + (new_char - 'a');
            else if ((new_char >= 'A') && (new_char <= 'F'))
                hex_val = hex_val * 16 + 10 + (new_char - 'A');
            else
                assert(0);
            if (++num_digits == 2)
            {
                data[length++] = hex_val;
                state = PARAGRAPH;
            }
            break;
        }
        // Don't allow a buffer overrun.
        assert(previous_offset + length < sizeof(msg_buf));
    }
    // End-of-file. Return everything we have so far.
    end_offset = previous_offset + length;
}

void NHttpTestInput::flush(uint32_t num_octets)
{
    flush_octets = previous_offset + num_octets;
    flushed = true;
}

void NHttpTestInput::discard(uint32_t num_octets)
{
    flush_octets = previous_offset + num_octets;
    just_flushed = true;
}

void NHttpTestInput::reassemble(uint8_t** buffer, unsigned& length, SourceId source_id, const
    NHttpFlowData* session_data,
    bool& tcp_close)
{
    if (!flushed || (source_id != last_source_id))
    {
        *buffer = nullptr;
        return;
    }
    *buffer = msg_buf;

    if (flush_octets <= end_offset)
    {
        // All the data we need comes from the file
        tcp_close = tcp_closed && (flush_octets == end_offset);
        length = flush_octets;
        just_flushed = true;
        flushed = false;
    }
    else
    {
        // We need to generate additional data to fill out the body or chunk section. We may come
        // through here
        // multiple times as we generate all the maximum size body sections needed for a single
        // flush.
        tcp_close = false;
        unsigned paf_max = DATABLOCKSIZE;
        if (session_data->section_type[source_id] == SEC_CHUNK) {
            paf_max -= session_data->section_buffer_length[source_id];
        }
        length = (flush_octets <= paf_max) ? flush_octets : paf_max;
        for (uint32_t k = end_offset; k < length; k++)
        {
            msg_buf[k] = 'A' + k % 26;
        }
        flush_octets -= length;
        end_offset = 0;
        if (flush_octets == 0)
        {
            just_flushed = true;
            flushed = false;
        }
    }
}

