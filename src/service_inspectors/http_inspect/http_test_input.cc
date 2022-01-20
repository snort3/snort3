//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/packet.h"

#include "http_common.h"
#include "http_enum.h"
#include "http_module.h"
#include "http_test_manager.h"

using namespace HttpCommon;
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

static void parse_next_hex_half_byte(const char new_char, uint8_t& hex_val)
{
    if ((new_char >= '0') && (new_char <= '9'))
        hex_val = hex_val * 16 + (new_char - '0');
    else if ((new_char >= 'a') && (new_char <= 'f'))
        hex_val = hex_val * 16 + 10 + (new_char - 'a');
    else if ((new_char >= 'A') && (new_char <= 'F'))
        hex_val = hex_val * 16 + 10 + (new_char - 'A');
    else
        assert(false);
}

static uint8_t get_hex_byte(const char buffer[])
{
    unsigned offset = 0;
    assert(*buffer == '\\');
    offset++;
    assert((*(buffer + offset) == 'X') or (*(buffer + offset) == 'x'));
    offset++;
    uint8_t hex_val = 0;
    parse_next_hex_half_byte (*(buffer + offset++), hex_val);
    parse_next_hex_half_byte (*(buffer + offset++), hex_val);
    return hex_val;
}

static bool is_number(const char buffer[], const unsigned length)
{
    for (unsigned k = 0; k < length; k++)
    {
        if (buffer[k] < '0' || buffer[k] > '9')
            return false;
    }
    return true;
}

HttpTestInput::HttpTestInput(const char* file_name)
{
    if ((test_data_file = fopen(file_name, "r")) == nullptr)
        throw std::runtime_error("Cannot open test input file");
}

HttpTestInput::~HttpTestInput()
{
    fclose(test_data_file);
}

void HttpTestInput::reset()
{
    flushed = false;
    last_source_id = SRC_CLIENT;
    just_flushed = false;
    tcp_closed = false;
    flush_octets = 0;
    need_break = false;
    reassembled_octets = 0;

    for (int k = 0; k <= 1; k++)
    {
        previous_offset[k] = 0;
        end_offset[k] = 0;
        if (include_file[k] != nullptr)
        {
            fclose(include_file[k]);
            include_file[k] = nullptr;
        }
        while (!segments[k].empty())
        {
            segments[k].pop();
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
    if (seq_num != curr_seq_num)
    {
        assert(source_id == SRC_CLIENT);
        curr_seq_num = seq_num;
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
        // StreamSplitter just flushed and it has all been sent by reassemble(). There may or may
        // not be leftover data from the last paragraph that was not flushed.
        just_flushed = false;
        data = msg_buf[last_source_id];
        assert(segments[last_source_id].empty());
        // compute the leftover data
        assert(flush_octets <= end_offset[last_source_id]);
        end_offset[last_source_id] = (end_offset[last_source_id] - flush_octets);
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
        const uint32_t last_seg_length =
            end_offset[last_source_id] - previous_offset[last_source_id];
        if (last_seg_length > 0)
            segments[last_source_id].push(last_seg_length);
        previous_offset[last_source_id] = end_offset[last_source_id];
        data = msg_buf[last_source_id] + previous_offset[last_source_id];
    }

    // Now we need to move forward by reading more data from the file
    int new_char;
    enum State { WAITING, COMMENT, COMMAND, PARAGRAPH, ESCAPE, HEXVAL, INSERT};
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
            else if (new_char == '$')
            {
                state = INSERT;
                command_length = 0;
            }
            else if (new_char != '\n')
            {
                state = PARAGRAPH;
                ending = false;
                msg_buf[last_source_id][end_offset[last_source_id]++] = (uint8_t)new_char;
            }
            else if (ending)
            {
                // An insert command was not followed by regular paragraph data
                length = end_offset[last_source_id] - previous_offset[last_source_id];
                return;
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
                    length = 0;
                    return;
                }
                else if ((command_length == strlen("response")) && !memcmp(command_value,
                    "response", strlen("response")))
                {
                    last_source_id = SRC_SERVER;
                    length = 0;
                    return;
                }
                else if ((command_length == strlen("break")) && !memcmp(command_value, "break",
                    strlen("break")))
                {
                    reset();
                    need_break = true;
                    length = 0;
                    return;
                }
                else if ((command_length == strlen("tcpclose")) && !memcmp(command_value,
                    "tcpclose", strlen("tcpclose")))
                {
                    tcp_closed = true;
                    length = 0;
                    return;
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
                else if (command_length > 0)
                {
                    // Look for a test number
                    if (is_number(command_value, command_length))
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
        case INSERT:
            if (new_char == '\n')
            {
                state = WAITING;
                ending = true;
                if ((command_length > strlen("fill")) && !memcmp(command_value, "fill",
                    strlen("fill")))
                {
                    const unsigned amount = convert_num_octets(command_value + strlen("fill"),
                        command_length - strlen("fill"));
                    assert((amount > 0) && (amount <= MAX_OCTETS and
                        (amount < sizeof(msg_buf[last_source_id]) - end_offset[last_source_id])));
                    for (unsigned k = 0; k < amount; k++)
                    {
                        // auto-fill ABCDEFGHIJABCD ...
                        msg_buf[last_source_id][end_offset[last_source_id]++] = 'A' + k%10;
                    }
                }
                else if ((command_length > strlen("fileread")) && !memcmp(command_value,
                    "fileread", strlen("fileread")))
                {
                    // Read the specified number of octets from the included file into the message
                    // buffer and return the resulting segment
                    const unsigned amount = convert_num_octets(command_value + strlen("fileread"),
                        command_length - strlen("fileread"));
                    assert((amount > 0) && (amount <= MAX_OCTETS and
                        (amount < sizeof(msg_buf[last_source_id]) - end_offset[last_source_id])));
                    for (unsigned k=0; k < amount; k++)
                    {
                        const int new_octet = getc(include_file[last_source_id]);
                        assert(new_octet != EOF);
                        msg_buf[last_source_id][end_offset[last_source_id]++] = new_octet;
                    }
                }
                else if ((command_length > strlen("h2frameheader")) && !memcmp(command_value,
                    "h2frameheader", strlen("h2frameheader")))
                {
                    generate_h2_frame_header(command_value, command_length);
                }
                else if ((command_length == strlen("h2preface")) && !memcmp(command_value,
                    "h2preface", strlen("h2preface")))
                {
                    char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    memcpy(msg_buf[last_source_id] + end_offset[last_source_id], preface, sizeof(preface) - 1);
                    end_offset[last_source_id] += sizeof(preface) - 1;
                }
                else
                {
                    // Bad command in test file
                    assert(false);
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
                else
                {
                    length = end_offset[last_source_id] - previous_offset[last_source_id];
                    return;
                }
            }
            else if (ending and new_char == '$')
            {
                // only look for insert commands at the start of a line
                state = INSERT;
                command_length = 0;
                ending = false;
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
            case '@':
            case '$':
            case '\\':
                state = PARAGRAPH;
                msg_buf[last_source_id][end_offset[last_source_id]++] = new_char;
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
            parse_next_hex_half_byte(new_char, hex_val);
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
    length = end_offset[last_source_id] - previous_offset[last_source_id];
}

void HttpTestInput::flush(uint32_t num_octets)
{
    if ((num_octets > 0) || (segments[last_source_id].size() == 0))
    {
        segments[last_source_id].push(num_octets);
    }

    flush_octets = previous_offset[last_source_id] + num_octets;
    reassembled_octets = 0;
    assert(flush_octets <= end_offset[last_source_id]);
    assert(flush_octets <= MAX_OCTETS);
    flushed = true;
}

void HttpTestInput::reassemble(uint8_t** buffer, unsigned& length, unsigned& total,
    unsigned& offset, uint32_t& flags, SourceId source_id, bool& tcp_close)
{
    *buffer = nullptr;
    tcp_close = false;

    // Only piggyback on data moving in the same direction.
    if (source_id != last_source_id)
        return;

    if (tcp_closed)
    {
        // Give the caller a chance to call finish()
        tcp_close = true;
        return;
    }

    // Need flushed data
    if (!flushed)
    {
        return;
    }

    total = flush_octets;
    assert(!segments[last_source_id].empty());
    const uint32_t segment_length = segments[last_source_id].front();
    segments[last_source_id].pop();

    length = segment_length;
    offset = reassembled_octets;
    *buffer = msg_buf[last_source_id] + reassembled_octets;
    reassembled_octets += length;
    if (!segments[last_source_id].empty())
    {
        // Not the final TCP segment to be reassembled
        flags &= ~PKT_PDU_TAIL;
    }
    else
    {
        // Final segment split at flush point
        assert(total == reassembled_octets);
        just_flushed = true;
        flushed = false;
    }

    return;
}

static uint8_t parse_frame_type(const char buffer[], const unsigned bytes_remaining,
    unsigned& bytes_consumed)
{
    uint8_t frame_type = 0;
    bytes_consumed = 0;
    for (; bytes_consumed < bytes_remaining and buffer[bytes_consumed] == ' '; bytes_consumed++);
    unsigned length = 0;
    for (; (bytes_consumed + length < bytes_remaining) and (buffer[bytes_consumed + length] != ' ');
        length++);

    static const char* frame_names[10] =
        { "data", "headers", "priority", "rst_stream", "settings", "push_promise", "ping", "goaway",
        "window_update", "continuation" };
    for (int i = 0; i < 10; i ++)
    {
        if (length == strlen(frame_names[i]) && !memcmp(buffer + bytes_consumed, frame_names[i],
            strlen(frame_names[i])))
        {
            frame_type = i;
            bytes_consumed += length;
            return frame_type;
        }
    }
    if (is_number(buffer + bytes_consumed, length))
        frame_type = convert_num_octets(buffer + bytes_consumed, length);
    else
        assert(false);

    bytes_consumed += length;
    return frame_type;
}


// Can be decimal or hex value. The hex value is represented as a series of 4-character hex bytes
// The hex value must not be more than 24-bits
static uint32_t get_frame_length(const char buffer[], const unsigned bytes_remaining,
    unsigned& bytes_consumed)
{
    bytes_consumed = 0;
    uint32_t frame_length = 0;
    for (; bytes_consumed < bytes_remaining and buffer[bytes_consumed] == ' '; bytes_consumed++);
    unsigned length = 0;
    for (; (bytes_consumed + length < bytes_remaining) and (buffer[bytes_consumed + length] != ' ');
        length++);
    if (is_number(buffer + bytes_consumed, length))
    {
        frame_length = convert_num_octets(buffer + bytes_consumed, length);
        bytes_consumed += length;
    }
    else
    {
        assert(length >=3 and length <= 12 and length % 4 == 0);
        unsigned end = bytes_consumed + length;
        while (bytes_consumed < end)
        {
            frame_length <<= 8;
            frame_length += get_hex_byte(buffer + bytes_consumed);
            bytes_consumed += 4;
        }
    }
    return frame_length;
}

// Hex value represented as \xnn -- always 4 characters long
static uint8_t get_frame_flags(const char buffer[], const unsigned bytes_remaining,
    unsigned& bytes_consumed)
{
    bytes_consumed = 0;
    for (; bytes_consumed < bytes_remaining and buffer[bytes_consumed] == ' '; bytes_consumed++);
    assert(bytes_remaining >= 4);
    uint8_t frame_flags = get_hex_byte(buffer + bytes_consumed);
    bytes_consumed += 4;
    return frame_flags;
}

// Check for optional stream_id in input. Default to stream 0 if not included
static uint32_t get_frame_stream_id(const char buffer[], const int bytes_remaining)
{
    int offset = 0;
    for (; offset < bytes_remaining and buffer[offset] == ' '; offset++);
    assert (bytes_remaining - offset >= 0);
    int length = 0;
    for (; (offset + length < bytes_remaining) and (buffer[offset + length] != ' '); length++);
    if (length > 0)
    {
        if (is_number(buffer + offset, length))
            return convert_num_octets(buffer + offset, length);
        else
            assert(false);
    }
    return 0;
}

void HttpTestInput::generate_h2_frame_header(const char command_value[], const unsigned command_length)
{
    unsigned offset = strlen("h2frameheader");
    unsigned bytes_consumed = 0;
    uint8_t frame_type = 0;
    uint8_t frame_flags = 0;
    uint32_t frame_length = 0;
    uint64_t stream_id = 0;

    // get the frame type
    frame_type = parse_frame_type(command_value + offset, command_length - offset, bytes_consumed);
    offset += bytes_consumed;

    frame_length = get_frame_length(command_value + offset, command_length - offset, bytes_consumed);
    offset += bytes_consumed;

    assert (offset < command_length);
    frame_flags = get_frame_flags(command_value + offset, command_length - offset, bytes_consumed);
    offset += bytes_consumed;

    stream_id = get_frame_stream_id(command_value + offset, command_length - offset);

    // write the frame header
    assert (!((frame_length >> (8*3)) & 0xFF));
    msg_buf[last_source_id][end_offset[last_source_id]++] = (frame_length >> 16) & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = (frame_length >> 8) & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = frame_length & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = frame_type;
    msg_buf[last_source_id][end_offset[last_source_id]++] = frame_flags;
    msg_buf[last_source_id][end_offset[last_source_id]++] = (stream_id >> 24) & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = (stream_id >> 16) & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = (stream_id >> 8) & 0xFF;
    msg_buf[last_source_id][end_offset[last_source_id]++] = stream_id & 0xFF;
}

bool HttpTestInput::finish()
{
    if (tcp_closed)
    {
        tcp_closed = false;
        return true;
    }
    return false;
}
#endif

