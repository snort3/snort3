//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// ssl_splitter.h author Steven Baigal <sbaigal@cisco.com>

#ifndef SSL_SPLITTER_H
#define SSL_SPLITTER_H

// Protocol aware flushing for SSL
// TLSPlaintext records are flushed when end-of-record meets end-of segment
// The splitter supports both sslv2 and sslv3 record format, 
// it starts by checking the first byte, if it is a valid sslv3 content type, 
// mark the session as sslv3; else if the MSB bit was set, marks it as sslv2,
// if this bit is not set, yet the session was marked sslv2 from prior detection,
// continue as sslv2

#include "stream/stream_splitter.h"

// Enumerations for PAF states
enum SslPafStates
{
    SSL_PAF_STATES_START = 0, //start, detect the ssl version, sslv3 type or sslv2 byte-0
    SSL_PAF_STATES_VER_MJR, // version major
    SSL_PAF_STATES_VER_MNR, // version minor
    SSL_PAF_STATES_LEN1,    // length byte-0
    SSL_PAF_STATES_LEN2,    // length byte-1
    SSL_PAF_STATES_DATA,    // fragment
    SSL_PAF_STATES_LEN2_V2, // sslv2, length byte-1
    SSL_PAF_STATES_PAD_V2,  // sslv2, padding byte if needed 
};

class SslSplitter : public snort::StreamSplitter
{
public:
    SslSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

private:
    SslPafStates paf_state;
    uint16_t remain_len;
    uint8_t len_bytes[2]; // temporary buffer to hold 2-byte length field
    bool is_sslv2;
};

#endif
