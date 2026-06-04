//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifndef STATS_RESPONSE_BUF_H
#define STATS_RESPONSE_BUF_H

#include <cstddef>
#include <streambuf>

#include "log/messages.h"

class ControlConn;

namespace snort
{

// This class can be used to help stream formats that might have large output
// lines that could exceed the control connection buffer size.
class StatsResponseBuf : public std::streambuf
{
public:
    explicit StatsResponseBuf(ControlConn*);
    ~StatsResponseBuf() override;

protected:
    int sync() override;
    int_type overflow(int_type) override;

private:
    static constexpr std::size_t RESPONSE_BUFFER_SIZE = 1024;
    static_assert(RESPONSE_BUFFER_SIZE < STD_BUF,
        "Stats response chunks must fit in ControlConn::respond()");

    int flush();
    bool send_chunk(const char*) const;

    ControlConn* ctrlcon;
    char buffer[RESPONSE_BUFFER_SIZE];
};

}

#endif
