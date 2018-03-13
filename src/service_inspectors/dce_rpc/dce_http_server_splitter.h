//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// dce_http_server_splitter.h author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifndef DCE_HTTP_SERVER_SPLITTER
#define DCE_HTTP_SERVER_SPLITTER

#include "dce_common.h"
#include "stream/stream_splitter.h"

class DceHttpServerSplitter : public snort::StreamSplitter
{
public:
    DceHttpServerSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;
//  FIXIT-M - Should be able to implement but framework does not permit
/*    const StreamBuffer* reassemble(Flow*, unsigned, unsigned,
        const uint8_t*, unsigned len, uint32_t, unsigned& copied)
    {
        copied = len;
        return nullptr;
    }*/
    bool is_paf() override
    {
        return true;
    }

    bool cutover_inspector()
    {
        return cutover;
    }

private:
    Status match(const uint8_t* data, uint32_t& len);
    unsigned int match_index;
    bool cutover;
};

#endif

