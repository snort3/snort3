//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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

// tlv_pdu_splitter.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "tlv_pdu.h"

using namespace snort;

//-------------------------------------------------------------------------
// splitter foo
//-------------------------------------------------------------------------

void TlvPduSplitter::scan_reset()
{
    value = 0;
    index = 0;
}

bool TlvPduSplitter::scan_once(unsigned prefix, const uint8_t* data, uint32_t len, uint32_t& fp)
{
    // tag
    while (index < config.offset and 0 < len)
    {
        ++index;
        ++data;
        --len;
    }

    // length
    while (index < prefix and 0 < len)
    {
        value <<= 8;
        value |= *data;
        ++index;
        ++data;
        --len;
    }

    // not enough data
    if (index < prefix)
        return false;

    // full TLV found
    fp = value;
    scan_reset();

    return true;
}

StreamSplitter::Status TlvPduSplitter::scan(Packet*, const uint8_t* data, uint32_t len, uint32_t, uint32_t* fp)
{
    ++pdu_counts.scans;

    const auto* guard = data + len;
    const auto prefix = config.offset + config.size;
    const auto header = config.offset + config.size + config.skip;

    auto pdus = config.max_pipelined;
    uint32_t carry = index;
    uint32_t fpc = 0;

    *fp = 0;

    // try to find as many as possible in the current segment
    while (data < guard and pdus and scan_once(prefix, data, len, fpc))
    {
        --pdus;

        if (config.relative)
        {
            if (fpc > UINT32_MAX - header)
            {
                ++pdu_counts.aborts;
                return ABORT;
            }
            fpc += header;
        }
        else if (fpc < header)
        {
            ++pdu_counts.aborts;
            return ABORT;
        }

        if (fpc < carry)
        {
            ++pdu_counts.aborts;
            return ABORT;
        }

        // adjust for data found in the previous scan
        fpc -= carry;
        carry = 0;

        // do not delay flush if a complete TLV has become available in the current scan
        if (*fp > 0 and fpc > len)
            break;

        // proceed to the next TLV
        *fp += fpc;

        if (fpc > len)
             break;

        data += fpc;
        len -= fpc;
    }

    if (!*fp)
        return SEARCH;

    ++pdu_counts.flushes;

    scan_reset();

    return FLUSH;
}
