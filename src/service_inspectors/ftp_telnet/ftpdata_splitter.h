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
// ftpdata_splitter.h author davis mcpherson <davmcphe@cisco.com>

#ifndef FTPDATA_SPLITTER_H
#define FTPDATA_SPLITTER_H

#include "stream/flush_bucket.h"
#include "stream/stream_splitter.h"

namespace snort
{
class Flow;
}

//---------------------------------------------------------------------------------
// FtpDataSplitter - flush when current seg size is different from previous segment
//---------------------------------------------------------------------------------
class FtpDataSplitter : public snort::StreamSplitter
{
public:
    FtpDataSplitter(bool b, uint16_t sz = 0) : snort::StreamSplitter(b)
    {
        min = sz + get_flush_bucket_size();
        restart_scan();
        expected_seg_size = 0;
    }


    Status scan(snort::Flow*, const uint8_t*, uint32_t len, uint32_t flags, uint32_t* fp ) override;
    bool finish(snort::Flow*) override;

private:
    uint16_t min;
    uint16_t segs;
    uint16_t bytes;
    uint16_t expected_seg_size;

    void restart_scan();
};

#endif
