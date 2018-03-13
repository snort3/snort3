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

#ifndef FTP_SPLITTER_H
#define FTP_SPLITTER_H

#include "stream/stream_splitter.h"

class FtpSplitter : public snort::StreamSplitter
{
public:
    FtpSplitter(bool c2s);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }
};

#endif

