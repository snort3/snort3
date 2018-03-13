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

// ssl_splitter.cc author Steven Baigal <sbaigal@cisco.com>

#include "ssl_splitter.h"

#include <arpa/inet.h>

#include "protocols/ssl.h"

using namespace snort;

SslSplitter::SslSplitter(bool c2s) : StreamSplitter(c2s)
{
    paf_state = SSL_PAF_STATES_START;
    remain_len = 0;
    len_bytes[0] = len_bytes[1] = 0;
    is_sslv2 = false;
}

StreamSplitter::Status SslSplitter::scan(
    Flow*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    uint32_t n = 0;
    uint32_t skip_len = 0;
    uint32_t last_fp = 0;

    while (n < len)
    {
        switch (paf_state)
        {
        case SSL_PAF_STATES_START:
            if (data[n] >= SSL_CHANGE_CIPHER_REC and data[n] <= SSL_HEARTBEAT_REC)
            {
                is_sslv2 = false;
                paf_state = SSL_PAF_STATES_VER_MJR;
            }
            else if ((data[n] & 0x80) or is_sslv2)
            {
                len_bytes[0] = data[n];
                is_sslv2 = true;
                paf_state = SSL_PAF_STATES_LEN2_V2;
            }
            else 
            {
                // unknown
                if (last_fp > 0)
                {
                    // stop here and flush out the good records
                    // it will come to ABORT on subsequent scan
                    n = len;
                }
                else
                {
                    return StreamSplitter::ABORT;
                }
            }
            break;
        case SSL_PAF_STATES_VER_MJR:
            paf_state = SSL_PAF_STATES_VER_MNR;
            break;
        case SSL_PAF_STATES_VER_MNR:
            paf_state = SSL_PAF_STATES_LEN1;
            break;
        case SSL_PAF_STATES_LEN1:
            len_bytes[0] = data[n];
            paf_state = SSL_PAF_STATES_LEN2;
            break;
        case SSL_PAF_STATES_LEN2:
            len_bytes[1] = data[n];
            remain_len = (len_bytes[0] << 8) + len_bytes[1];
            if (remain_len == 0)
            {
                last_fp = n;
                paf_state = SSL_PAF_STATES_START;
            }
            else
            {
                paf_state = SSL_PAF_STATES_DATA;
            }
            break;
        case SSL_PAF_STATES_DATA:
            skip_len = ((len-n) > remain_len) ? remain_len : (len - n);
            remain_len -= skip_len;
            n += skip_len;
            if (remain_len == 0)
            {
                last_fp = n;
                paf_state = SSL_PAF_STATES_START;
            }
            n--;
            break;
        case SSL_PAF_STATES_LEN2_V2:
            len_bytes[1] = data[n];
            if (len_bytes[0] & 0x80)
            {
                // sslv2 using 2-byte length
                len_bytes[0] = len_bytes[0] & 0x7F;
                paf_state = SSL_PAF_STATES_DATA;
            }
            else
            {
                // sslv2 using 3-byte length
                len_bytes[0] = len_bytes[0] & 0x3F;
                paf_state = SSL_PAF_STATES_PAD_V2;
            }
            remain_len = (len_bytes[0] << 8) + len_bytes[1];
            break;
        case SSL_PAF_STATES_PAD_V2:
            paf_state = SSL_PAF_STATES_DATA;
            break;
        }

        n++;
    }
    // if a flush point was found, flush from there
    if (last_fp > 0)
    {
        *fp = last_fp;
        remain_len = 0;
        paf_state = SSL_PAF_STATES_START;
        return StreamSplitter::FLUSH;
    }

    return StreamSplitter::SEARCH;
}

