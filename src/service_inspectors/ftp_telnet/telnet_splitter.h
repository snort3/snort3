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

#ifndef TELNET_SPLITTER_H
#define TELNET_SPLITTER_H

#include "stream/stream_splitter.h"
#include "pp_telnet.h"

class TelnetSplitter : public snort::StreamSplitter
{
public:
    TelnetSplitter(bool c2s);

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }
private:
    enum TelnetState { TELNET_NONE, TELNET_IAC, TELNET_IAC_SB, TELNET_IAC_SB_IAC };
    TelnetState state { TELNET_NONE };
};

#endif

