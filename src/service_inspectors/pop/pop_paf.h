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

// pop_paf.h author: Hui Cao <huica@cisco.com>

#ifndef POP_PAF_H
#define POP_PAF_H

// Protocol aware flushing for POP.

#include "mime/file_mime_paf.h"
#include "stream/stream_splitter.h"

// Structure used to record expected server termination sequence
enum PopExpectedResp
{
    POP_PAF_SINGLE_LINE_STATE,      // server response will end with \r\n
    POP_PAF_MULTI_LINE_STATE,       // server response will end with \r\n.\r\n
    POP_PAF_DATA_STATE,             // Indicated MIME will be contained in response
    POP_PAF_HAS_ARG                 // Intermediate state when parsing LIST
};

enum PopParseCmdState
{
    POP_CMD_SEARCH,         // Search for Command
    POP_CMD_FIN,            // Found space. Finished parsing Command
    POP_CMD_ARG             // Parsing command with multi-line response iff arg given
};

// saves data when parsing client commands
struct PopPafParseCmd
{
    const char* next_letter;        // a pointer to the current commands data
    PopExpectedResp exp_resp;       // the expected termination sequence for this command
    PopParseCmdState status;        // whether the current has already been found
};

// State tracker for POP PAF
struct PopPafData
{
    PopExpectedResp pop_state;       // The current POP PAF state.
    PopPafParseCmd cmd_state;        // all of the command parsing data
    DataEndState end_state;          // Current termination sequence state
    MimeDataPafInfo data_info;       // Mime Information
    bool cmd_continued;              // data continued from previous packet?
    bool end_of_data;
};

class PopSplitter : public snort::StreamSplitter
{
public:
    PopSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

public:
    PopPafData state;
};

// Function: Callback to check if POP data end is reached
bool pop_is_data_end(snort::Flow* ssn);

#endif

