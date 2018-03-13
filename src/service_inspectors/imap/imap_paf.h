//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// imap_paf.h author Hui Cao <huica@cisco.com>

#ifndef IMAP_PAF_H
#define IMAP_PAF_H

// Protocol aware flushing for IMAP

#include "mime/file_mime_paf.h"
#include "stream/stream_splitter.h"

struct ImapDataInfo
{
    int paren_cnt;            // The open parentheses count in fetch
    const char* next_letter;  // The current command in fetch
    bool found_len;
    uint32_t length;
    bool esc_nxt_char;        // true if the next character has been escaped
};

// States for IMAP PAF
typedef enum _ImapPafState
{
    IMAP_PAF_REG_STATE,           // default state. eat until LF
    IMAP_PAF_DATA_HEAD_STATE,     // parses the fetch header
    IMAP_PAF_DATA_LEN_STATE,      // parse the literal length
    IMAP_PAF_DATA_STATE,          // search for and flush on MIME boundaries
    IMAP_PAF_FLUSH_STATE,         // flush if a termination sequence is found
    IMAP_PAF_CMD_IDENTIFIER,      // determine the line identifier ('+', '*', tag)
    IMAP_PAF_CMD_TAG,             // currently analyzing tag . identifier
    IMAP_PAF_CMD_STATUS,          // currently parsing second argument
    IMAP_PAF_CMD_SEARCH           // currently searching data for a command
} ImapPafState;

typedef enum _ImapDataEnd
{
    IMAP_PAF_DATA_END_UNKNOWN,
    IMAP_PAF_DATA_END_PAREN
} ImapDataEnd;

// State tracker for IMAP PAF
struct ImapPafData
{
    MimeDataPafInfo mime_info;    // Mime response information
    ImapPafState imap_state;      // The current IMAP paf stat
    ImapDataInfo imap_data_info;  // Used for parsing data
    ImapDataEnd data_end_state;
    bool end_of_data;
};

class ImapSplitter : public snort::StreamSplitter
{
public:
    ImapSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

public:
    ImapPafData state;
};

// Function: Check if IMAP data end is reached
bool imap_is_data_end(snort::Flow* ssn);

#endif

