//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

//--------------------------------------------------------------------
// hi stuff
//
// @file    hi_stream_splitter.h
// @author  Russ Combs <rcombs@sourcefire.com>
//--------------------------------------------------------------------

#ifndef HI_STREAM_SPLITTER_H
#define HI_STREAM_SPLITTER_H

#include "main/snort_types.h"
#include "stream/stream_api.h"
#include "stream/stream_splitter.h"

bool hi_paf_init(uint32_t cap);
void hi_paf_term();

bool hi_paf_simple_request(Flow*);

struct Hi5State
{
    uint32_t len;
    uint16_t flags;
    uint8_t msg;
    uint8_t fsm;
    uint32_t pipe;
};

class HttpSplitter : public StreamSplitter
{
public:
    HttpSplitter(bool c2s);
    ~HttpSplitter();

    Status scan(Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    virtual bool is_paf() override { return true; }

public:
    Hi5State state;
};

#endif

