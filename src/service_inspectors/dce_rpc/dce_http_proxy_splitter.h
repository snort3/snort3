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

// dce_http_proxy_splitter.h author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifndef DCE_HTTP_PROXY_SPLITTER
#define DCE_HTTP_PROXY_SPLITTER

#include "dce_common.h"
#include "stream/stream_splitter.h"

class DceHttpProxySplitter : public snort::StreamSplitter
{
public:
    DceHttpProxySplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    const snort::StreamBuffer reassemble(snort::Flow*, unsigned, unsigned,
        const uint8_t*, unsigned, uint32_t, unsigned&) override;

    bool is_paf() override
    { return true; }

    bool cutover_inspector()
    { return cutover; }

private:
    Status match_request_head(const uint8_t* data, uint32_t& len);
    Status match_response_head(const uint8_t* data, uint32_t& len);
    Status match_response(const uint8_t* data, uint32_t& len);

    enum DceHttpProxyState
    {
        HTTP_PROXY_INIT = 0,
        HTTP_PROXY_HEAD = 1,
        HTTP_PROXY_FIRST_NL = 2,
    };

    DceHttpProxyState match_state;
    unsigned int match_index;
    bool cutover;
};

#endif

