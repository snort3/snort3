//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_stream_splitter_base.h author Shibin K V <shikv@cisco.com>

#ifndef HTTP_STREAM_SPLITTER_BASE_H
#define HTTP_STREAM_SPLITTER_BASE_H

#include "main/snort_types.h"
#include "stream/stream_splitter.h"

class SO_PUBLIC HttpStreamSplitterBase : public snort::StreamSplitter
{
public:
    virtual ~HttpStreamSplitterBase() override = default;

    virtual void prep_partial_flush(snort::Flow* flow, uint32_t num_flush) = 0;

    virtual Status scan(snort::Flow* flow, const uint8_t* data, uint32_t length, uint32_t* flush_offset) = 0;
protected:
    HttpStreamSplitterBase(bool c2s) : StreamSplitter(c2s) { }
private:
    using snort::StreamSplitter::scan;
};

#endif

