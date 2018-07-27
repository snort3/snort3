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
// sip_splitter.h author Hui Cao <huica@cisco.com>
// sip_splitter.h author Pratik Shinde <pshinde2@cisco.com>

#ifndef SIP_SPLITTER_H
#define SIP_SPLITTER_H
// Protocol aware flushing for sip

#include "stream/stream_splitter.h"

enum SipPafStates
{
    SIP_PAF_START_STATE = 0,     //Default state. Continue until LF
    SIP_PAF_CONTENT_LEN_CMD, //Searching Content-Length header
    SIP_PAF_CONTENT_LEN_CONVERT,   //Parse the literal content length
    SIP_PAF_BODY_SEARCH,    //Check SIP body start
    SIP_PAF_FLUSH_STATE     //Flush if Content-Length is reached
};

//State tracker for SIP Content Length
enum SipPafDataLenStatus
{
    SIP_PAF_LENGTH_INVALID,
    SIP_PAF_LENGTH_CONTINUE,
    SIP_PAF_LENGTH_DONE
};

//State tracker for SIP Body Boundary
enum SipPafBodyStatus
{
    SIP_PAF_BODY_UNKNOWN,
    SIP_PAF_BODY_START_FIRST_CR,   //Check SIP body start - first CR
    SIP_PAF_BODY_START_FIRST_LF,   //Check SIP body start - first LF
    SIP_PAF_BODY_START_SECOND_CR,  //Check SIP body start - second CR
    SIP_PAF_BODY_START_SECOND_LF  //Check SIP body start - second LF
};

#define UNKNOWN_CONTENT_LENGTH UINT32_MAX

class SipSplitter : public snort::StreamSplitter
{
public:
    SipSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

private:
    void reset_states();
    bool find_data_end_single_line(const uint8_t ch);
    void process_command(const uint8_t ch);
    SipPafDataLenStatus get_length(const uint8_t c);
    bool find_body(const uint8_t ch);

    static const char content_len_key[];
    static const char content_len_key_compact[];
    SipPafStates paf_state;
    SipPafBodyStatus body_state;  //State to find sip body
    const char *next_letter;     //The current character in Content-Length
    uint32_t content_length;

#ifdef UNIT_TEST
    friend class SipSplitterUT;
#endif

};
#endif
