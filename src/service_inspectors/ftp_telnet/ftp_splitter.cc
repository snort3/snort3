//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// ftp_splitter.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_splitter.h"
#include "protocols/ssl.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include <cstring>

using namespace snort;

FtpSplitter::FtpSplitter(bool c2s) : StreamSplitter(c2s) { }

// flush at last CR or LF in data
// preproc will deal with any pipelined commands
StreamSplitter::Status FtpSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
    if ( IsSSL(data, len, p->packet_flags) )
    {
        *fp = len;
        return FLUSH;
    }

    const uint8_t* cr = snort_memrchr(data, '\r', len);
    const uint8_t* lf = snort_memrchr(data, '\n', len);

    const uint8_t* ptr = nullptr;

    if ( cr && !lf )
        ptr = cr;
    else if ( !cr && lf )
        ptr = lf;
    else if ( cr && lf )
        ptr = ( cr > lf ) ? cr : lf;

    if ( !ptr )
        return SEARCH;

    *fp = ptr - data + 1;
    return FLUSH;
}

