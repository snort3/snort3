//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_pdu_splitter.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_pdu.h"

using namespace snort;

//-------------------------------------------------------------------------
// splitter foo
//-------------------------------------------------------------------------

StreamSplitter::Status TcpPduSplitter::scan(Packet*, const uint8_t* data, uint32_t len, uint32_t, uint32_t* fp)
{
    ++pdu_counts.scans;
    unsigned prefix = config.offset + config.size;

    for ( unsigned i = 0; i < len; ++i )
    {
        if ( index < config.offset )
            ++index;

        else if ( index < prefix )
        {
            ++index;
            value <<= 8;
            value |= data[i];
        }
        else
            break;
    }
    if ( index == prefix )
    {
        unsigned header = config.offset + config.size + config.skip;

        if ( config.relative )
            value += header;

        *fp = value;
        value = 0;
        index = 0;

        if ( config.relative or (*fp >= header) )
        {
            ++pdu_counts.flushes;
            return FLUSH;
        }
        ++pdu_counts.aborts;
        return ABORT;
    }
    return SEARCH;
}

