//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// ssh_splitter.h author Pranav Bhalerao <prbhaler@cisco.com>

#ifndef SSH_SPLITTER_H
#define SSH_SPLITTER_H

#include "protocols/packet.h"
#include "stream/stream_splitter.h"

#include "ssh.h"

enum SshPafState
{
    SSH_PAF_VER_EXCHANGE,
    SSH_PAF_KEY_EXCHANGE,
    SSH_PAF_ENCRYPTED
};

class SshSplitter : public snort::StreamSplitter
{
public:
    SshSplitter(bool c2s) : StreamSplitter(c2s)
    { }

    Status scan(snort::Packet*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override
    {
        return true;
    }

private:
    Status ssh2_key_exchange_scan(const uint8_t* data, uint32_t len,
        uint32_t* fp, uint32_t& remain_bytes);
    Status ssh2_scan(SSHData* sessp, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp);

    SshPafState state = SSH_PAF_VER_EXCHANGE;
    uint32_t client_remain_bytes = 0;
    uint32_t server_remain_bytes = 0;
};
#endif
