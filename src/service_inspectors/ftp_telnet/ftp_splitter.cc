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
// ftp_splitter.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ftp_splitter.h"

#include <cstring>

using namespace snort;

FtpSplitter::FtpSplitter(bool c2s) : StreamSplitter(c2s) { }

// flush at last line feed in data
// preproc will deal with any pipelined commands
StreamSplitter::Status FtpSplitter::scan(
    Flow*, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t* fp)
{
#ifdef HAVE_MEMRCHR
    uint8_t* lf =  (uint8_t*)memrchr(data, '\n', len);
#else
    uint32_t n = len;
    const uint8_t* lf = nullptr, * tmp = data;

    while ( (tmp = (const uint8_t*)memchr(tmp, '\n', n)) )
    {
        lf = tmp++;
        n = len - (tmp - data);
    }
#endif

    if ( !lf )
        return SEARCH;

    *fp = lf - data + 1;
    return FLUSH;
}

