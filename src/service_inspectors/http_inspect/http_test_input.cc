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
// http_test_input.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef REG_TEST

#include "http_test_input.h"

#include "http_module.h"
#include "http_test_manager.h"

using namespace HttpEnums;

static unsigned convert_num_octets(const char buffer[], unsigned length)
{
    unsigned amount = 0;
    for (unsigned k = 0; k < length; k++)
    {
        if ((buffer[k] >= '0') && (buffer[k] <= '9'))
        {
            amount = amount * 10 + (buffer[k] - '0');
        }
    }
    return amount;
}

HttpTestInput::HttpTestInput(const char* file_name)
{
    if ((test_data_file = fopen(file_name, "r")) == nullptr)
        throw std::runtime_error("Cannot open test input file");
}

void HttpTestInput::reset()
{
    flushed = false;
    last_source_id = SRC_CLIENT;
    just_flushed = true;
    tcp_closed = false;
    flush_octets = 0;
    close_pending = false;
    close_notified = false;
    finish_expected = false;
    need_break = false;

    for (int k = 0; k <= 1; k++)
    {
        previous_offset[k] = 0;
        end_offset[k] = 0;
        if (include_file[k] != nullptr)
        {
            fclose(include_file[k]);
            include_file[k] = nullptr;
        }
    }

    // Each test needs separate peg counts
    HttpModule::reset_peg_counts();
}

// Read from the test data file and present to StreamSplitter. In the process we may need to skip
// comments, execute simple commands, and handle escape sequences. The best way to understand this
// function is to read dev_notes.txt.
void HttpTestInput::scan(uint8_t*& data, uint32_t& length, SourceId source_id, uint64_t seq_num)
{
    bool skip_to_break = false;
    if (seq_num != curr_seq_num)
    {
        assert(source_id == SRC_CLIENT);
        curr_seq_num = seq_num;
        // If we have not yet found the break command we need to skim past everything and not
        // return any data until we find it.
        skip_to_break = !need_break;
        reset();
    }

    // Don't proceed if we have previously flushed data not reassembled yet.
    // Piggyback on traffic moving in the correct direction.
    // Once a break is read we must wait for a new flow.
    else if (flushed || (source_id != last_source_id) || need_break)
    {
        length = 0;
        return;
    }

    if (just_flushed)
    {
        // Beginning of a new test or StreamSplitter just flushed and it has all been sent by
        // reassemble(). There may or may not be leftover data from the last paragraph that was not
        // flushed.
        just_flushed = false;
        data = msg_buf[last_source_id];
        // compute the leftover data
        end_offset[last_source_id] = (flush_octets <= end_offset[last_source_id]) ?
            (end_offset[last_source_id] - flush_octets) : 0;
        previous_offset[last_source_id] = 0;
        if (end_offset[last_source_id] > 0)
        {
            // Must present unflushed leftovers to StreamSplitter again. If we don't take this
            // opportunity to left justify our data in the buffer we may "walk" to the right until
            // we run out of buffer space.
            memmove(msg_buf[last_source_id], msg_buf[last_source_id]+flush_octets,
                end_offset[last_source_id]);
            flush_octets = 0;
            length = end_offset[last_source_id];
            return;
        }
        // If we reach here then StreamSplitter has already flushed all data read so far
        flush_octets = 0;
    }
    else
    {
        // The data we gave StreamSplitter last time was not flushed
        previous_offset[last_source_id] = end_offset[last_source_id];
        data = msg_buf[last_source_id] + previous_offset[last_source_id];
    }

    // Now we need to move forward by reading more data from the file
    int new_char;
    enum State { WAITING, COMMENT, COMMAND, PARAGRAPH, ESCAPE, HEXVAL };
    State state = WAITING;
    bool ending = false;
    unsigned command_length = 0;
    const int max_command = 1000;
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
                msg_buf[last_source_id][end_offset[last_source_id]++] = (uint8_t)new_char;
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
                if ((command_length == strlen("request")) && !memcmp(command_value, "request",
                    strlen("request")))
                {
                    last_source_id = SRC_CLIENT;
                    if (!skip_to_break)
                    {
                        length = 0;
                        return;
                    }
                }
                else if ((command_length == strlen("response")) && !memcmp(command_value,
                    "response", strlen("response")))
                {
                    last_source_id = SRC_SERVER;
                    if (!skip_to_break)
                    {
                        length = 0;
                        return;
                    }
                }
                else if ((command_length == strlen("break")) && !memcmp(command_value, "break",
                    strlen("break")))
                {
                    reset();
                    if (!skip_to_break)
                        need_break = true;
                    length = 0;
                    return;
                }
                else if ((command_length == strlen("tcpclose")) && !memcmp(command_value,
                    "tcpclose", strlen("tcpclose")))
                {
                    tcp_closed = true;
                }
                else if ((command_length > strlen("fill")) && !memcmp(command_value, "fill",
                    strlen("fill")))
                {
                    const unsigned amount = convert_num_octets(command_value + strlen("fill"),
                        command_length - strlen("fill"));
                    assert((amount > 0) && (amount <= MAX_OCTETS));
                    for (unsigned k = 0; k < amount; k++)
                    {
                        // auto-fill ABCDEFGHIJABCD ...
                        msg_buf[last_source_id][end_offset[last_source_id]++] = 'A' + k%10;
                    }
                    if (skip_to_break)
                        end_offset[last_source_id] = 0;
                    else
                    {
                        length = end_offset[last_source_id] - previous_offset[last_source_id];
                        return;
                    }
                }
                else if ((command_length > strlen("fileset")) && !memcmp(command_value, "fileset",
                    strlen("fileset")))
                {
                    // Designate a file of data to be loaded into the message buffer
                    char include_file_name[max_command];
                    int offset = strlen("fileset");
                    for (; command_value[offset] == ' '; offset++);
                    unsigned k;
                    for (k=0; k < command_length - offset; k++)
                    {
                        include_file_name[k] = command_value[k+offset];
                    }
                    include_file_name[k] = '\0';
                    if (include_file[last_source_id] != nullptr)
                        fclose(include_file[last_source_id]);
                    if ((include_file[last_source_id] = fopen(include_file_name, "r")) == nullptr)
                        throw std::runtime_error("Cannot open test file to be included");
                }
                else if ((command_length > strlen("fileread")) && !memcmp(command_value,
                    "fileread", strlen("fileread")))
                {
                    // Read the specified number of octets from the included file into the message
                    // buffer and return the resulting segment
                    const unsigned amount = convert_num_octets(command_value + strlen("fileread"),
                        command_length - strlen("fileread"));
                    assert((amount > 0) && (amount <= MAX_OCTETS));
                    for (unsigned k=0; k < amount; k++)
                    {
                        const int new_octet = getc(include_file[last_source_id]);
                        assert(new_octet != EOF);
                        msg_buf[last_source_id][end_offset[last_source_id]++] = new_octet;
                    }
                    if (skip_to_break)
                        end_offset[last_source_id] = 0;
                    else
                    {
                        length = end_offset[last_source_id] - previous_offset[last_source_id];
                        return;
                    }
                }
                else if ((command_length > strlen("fileskip")) && !memcmp(command_value,
                    "fileskip", strlen("fileskip")))
                {
                    // Skip the specified number of octets from the included file
                    const unsigned amount = convert_num_octets(command_value + strlen("fileskip"),
                        command_length - strlen("fileskip"));
                    assert(amount > 0);
                    for (unsigned k=0; k < amount; k++)
                    {
                        getc(include_file[last_source_id]);
                    }
                }
                else if ((command_length == strlen("fileclose")) && !memcmp(command_value,
                    "fileclose", strlen("fileclose")))
                {
                    if (include_file[last_source_id] != nullptr)
                    {
                        fclose(include_file[last_source_id]);
                        include_file[last_source_id] = nullptr;
                    }
                }
                else if (command_length > 0)
                {
                    // Look for a test number
                    bool is_number = true;
                    for (unsigned k=0; (k < command_length) && is_number; k++)
                    {
                        is_number = (command_value[k] >= '0') && (command_value[k] <= '9');
                    }
                    if (is_number)
                    {
                        int64_t test_number = 0;
                        for (unsigned j=0; j < command_length; j++)
                        {
                            test_number = test_number * 10 + (command_value[j] - '0');
                        }
                        HttpTestManager::update_test_number(test_number);
                    }
                    else
                    {
                        // Bad command in test file
                        assert(false);
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
                    assert(false);
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
                if (!ending)
                {
                    ending = true;
                }
                // Found the second consecutive blank line that ends the paragraph.
                else if (skip_to_break)
                {
                    end_offset[last_source_id] = 0;
                    ending = false;
                    state = WAITING;
                }
                else
                {
                    length = end_offset[last_source_id] - previous_offset[last_source_id];
                    return;
                }
            }
            else
            {
                ending = false;
                msg_buf[last_source_id][end_offset[last_source_id]++] = (uint8_t)new_char;
            }
            break;
        case ESCAPE:
            switch (new_char)
            {
            case 'n':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '\n';
                break;
            case 'r':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '\r';
                break;
            case 't':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '\t';
                break;
            case '#':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '#';
                break;
            case '@':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '@';
                break;
            case '\\':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = '\\';
                break;
            case 'x':
            case 'X':
                state = HEXVAL;
                hex_val = 0;
                num_digits = 0;
                break;
            default:
                assert(false);
                state = PARAGRAPH;
                break;
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
                assert(false);
            if (++num_digits == 2)
            {
                msg_buf[last_source_id][end_offset[last_source_id]++] = hex_val;
                state = PARAGRAPH;
            }
            break;
        }
        // Don't allow a buffer overrun.
        assert(end_offset[last_source_id] < sizeof(msg_buf[last_source_id]));
    }
    // End-of-file. Return everything we have so far.
    if (skip_to_break)
        end_offset[last_source_id] = 0;
    length = end_offset[last_source_id] - previous_offset[last_source_id];
}

void HttpTestInput::flush(uint32_t num_octets)
{
    flush_octets = previous_offset[last_source_id] + num_octets;
    assert(flush_octets <= MAX_OCTETS);
    flushed = true;
}

void HttpTestInput::reassemble(uint8_t** buffer, unsigned& length, SourceId source_id,
    bool& tcp_close)
{
    *buffer = nullptr;
    tcp_close = false;

    // Only piggyback on data moving in the same direction.
    // Need flushed data unless the connection is closing.
    if ((source_id != last_source_id) || (!flushed && !tcp_closed))
    {
        return;
    }

    // How we process TCP close situations depends on the size of the flush relative to the data
    // buffer.
    // 1. less than whole buffer - not the final flush, ignore pending close
    // 2. exactly equal - process data now and signal the close next time around
    // 3. more than whole buffer - signal the close now and truncate and send next time around
    // 4. there was no flush - signal the close now and send the leftovers next time around
    if (tcp_closed && (!flushed || (flush_octets >= end_offset[last_source_id])))
    {
        if (close_pending)
        {
            // There is no more data. Clean up and notify caller about close.
            just_flushed = true;
            flushed = false;
            end_offset[last_source_id] = 0;
            previous_offset[last_source_id] = 0;
            close_pending = false;
            tcp_closed = false;
            tcp_close = true;
            finish_expected = true;
        }
        else if (!flushed)
        {
            // Failure to flush means scan() reached end of paragraph and returned PAF_SEARCH.
            // Notify caller about close and they will do a zero-length flush().
            previous_offset[last_source_id] = end_offset[last_source_id];
            tcp_close = true;
            close_notified = true;
            finish_expected = true;
        }
        else if (flush_octets == end_offset[last_source_id])
        {
            // The flush point is the end of the paragraph. Supply the data now and if necessary
            // notify the caller about close next time or otherwise just clean up.
            *buffer = msg_buf[last_source_id];
            length = flush_octets;
            if (close_notified)
            {
                just_flushed = true;
                flushed = false;
                close_notified = false;
                tcp_closed = false;
            }
            else
            {
                close_pending = true;
            }
        }
        else
        {
            // Flushed more body data than is actually available. Truncate the size of the flush,
            // notify caller about close, and supply the data next time.
            flush_octets = end_offset[last_source_id];
            tcp_close = true;
            close_notified = true;
            finish_expected = true;
        }
        return;
    }

    // Normal case with no TCP close or at least not yet
    *buffer = msg_buf[last_source_id];
    length = flush_octets;
    if (flush_octets > end_offset[last_source_id])
    {
        // We need to generate additional data to fill out the body or chunk section.
        for (uint32_t k = end_offset[last_source_id]; k < flush_octets; k++)
        {
            if (include_file[last_source_id] == nullptr)
            {
                msg_buf[last_source_id][k] = 'A' + k % 26;
            }
            else
            {
                int new_octet = getc(include_file[last_source_id]);
                assert(new_octet != EOF);
                msg_buf[last_source_id][k] = new_octet;
            }
        }
    }
    just_flushed = true;
    flushed = false;
}

bool HttpTestInput::finish()
{
    if (finish_expected)
    {
        finish_expected = false;
        return true;
    }
    return false;
}

#endif

