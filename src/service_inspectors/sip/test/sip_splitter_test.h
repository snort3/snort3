//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
//sip_splitter_test.h author Pratik Shinde <pshinde2@cisco.com>

#ifndef SIP_SPLITTER_TEST
#define SIP_SPLITTER_TEST
//Test for sip splitter

#include "stream/stream_splitter.h"
#include "service_inspectors/sip/sip_splitter.h"

//stubs to avoid link errors
const snort::StreamBuffer snort::StreamSplitter::reassemble(snort::Flow*, unsigned int, unsigned int,
    unsigned char const*, unsigned int, unsigned int, unsigned int &) { return {}; }
unsigned snort::StreamSplitter::max(snort::Flow *) { return 0; }

const uint8_t line_feed = '\n';
const uint8_t carriage_return = '\r';
const uint8_t no_lf_cr = '\t';

//characters recognized by isspace() as spaces
const uint8_t spaces[] = {' ', '\t', '\n', '\v', '\f', '\r'};

//character recognized by isblanck() as seperators 
const uint8_t blanks[] = {' ', '\t' };

class SipSplitterUT
{
public:
    SipSplitterUT(SipSplitter ss) : ss(ss) { };

    bool splitter_is_paf()
    { 
        return ss.is_paf();
    }

    void splitter_reset_states()
    { 
        ss.reset_states();
    }

    SipPafStates splitter_get_paf_state()
    { 
        return ss.paf_state; 
    }

    SipPafBodyStatus splitter_get_body_state()
    { 
        return ss.body_state;
    }

    const char* splitter_get_next_letter()
    {
        return ss.next_letter;
    }

    uint32_t splitter_get_content_length()
    {
        return ss.content_length;
    }

    const char* splitter_get_content_length_key()
    {
        return SipSplitter::content_len_key;
    }

    bool splitter_data_end_single_line(const uint8_t ch)
    {
        return ss.find_data_end_single_line(ch);
    }

    bool splitter_find_body(const uint8_t ch)
    {
        return ss.find_body(ch);
    }

    void splitter_set_content_length(uint32_t len)
    {
        ss.content_length = len;
    }

    void splitter_set_body_state(SipPafBodyStatus bstate)
    {
        ss.body_state = bstate;
    }

    void splitter_set_paf_state(SipPafStates pafstate)
    {
        ss.paf_state = pafstate;
    }

    void splitter_set_next_letter_last()
    {
        ss.next_letter = &SipSplitter::content_len_key_compact[1];
    }

    SipPafDataLenStatus splitter_get_length(const uint8_t ch)
    {
        return ss.get_length(ch);
    }

    void splitter_process_command(const uint8_t ch)
    {
        ss.process_command(ch);
    }

    snort::StreamSplitter::Status splitter_scan(snort::Flow *flow, const uint8_t* data,
                                uint32_t len, uint32_t flags, uint32_t* fp)
    {
        return ss.scan(flow, data, len, flags, fp);
    }

    bool is_init()
    {
        return ss.paf_state == SIP_PAF_START_STATE && ss.content_length == UNKNOWN_CONTENT_LENGTH &&
                        ss.next_letter == nullptr && ss.body_state == SIP_PAF_BODY_UNKNOWN;
    }

    const char * splitter_get_content_length_compact_key()
    {
        return SipSplitter::content_len_key_compact;
    }
private:
    SipSplitter ss;
};
#endif
