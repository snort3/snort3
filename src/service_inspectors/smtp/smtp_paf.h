//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// smtp_paf.h author Hui Cao <huica@ciso.com>

#ifndef SMTP_PAF_H
#define SMTP_PAF_H

// Protocol aware flushing for SMTP

#include "mime/file_mime_paf.h"
#include "stream/stream_splitter.h"

// State tracker for SMTP PAF
enum SmtpPafState
{
    SMTP_PAF_CMD_STATE,
    SMTP_PAF_DATA_STATE
};
// State tracker for data command
typedef enum _SmtpPafCmdState
{
    SMTP_PAF_CMD_UNKNOWN,
    SMTP_PAF_CMD_START,
    SMTP_PAF_CMD_DETECT,
    SMTP_PAF_CMD_DATA_LENGTH_STATE,
    SMTP_PAF_CMD_DATA_END_STATE
} SmtpPafCmdState;

struct SmtpCmdSearchInfo
{
    SmtpPafCmdState cmd_state;
    int search_id;
    const char* search_state;
};

// State tracker for SMTP PAF
struct SmtpPafData
{
    DataEndState data_end_state;
    uint32_t length;
    SmtpPafState smtp_state;
    SmtpCmdSearchInfo cmd_info;
    MimeDataPafInfo data_info;
    bool end_of_data;
};

class SmtpSplitter : public snort::StreamSplitter
{
public:
    SmtpSplitter(bool c2s, int max_auth_cmd_line_len);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

public:
    SmtpPafData state;

private:
    int max_auth_command_line_len;
};

// Function: Check if IMAP data end is reached
bool smtp_is_data_end(snort::Flow* ssn);

#endif
