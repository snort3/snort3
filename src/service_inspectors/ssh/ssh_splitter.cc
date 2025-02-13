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

// ssh_splitter.cc author Pranav Bhalerao <prbhaler@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh_splitter.h"
#include "ssh_module.h"

using namespace snort;

StreamSplitter::Status SshSplitter::ssh2_key_exchange_scan(
    const uint8_t* data, uint32_t len, uint32_t* fp,
    uint32_t& remain_bytes)
{
    if (remain_bytes < len)
    {
        if (remain_bytes != 0)
        {
            *fp = remain_bytes;
            return StreamSplitter::FLUSH;
        }
        const SSH2Packet* sshp = (const SSH2Packet*)data;
        uint32_t ssh_len = ntohl(sshp->packet_length) + SSH2_PACKET_LEN;
        if (ssh_len > len)
        {
            remain_bytes = ssh_len - len;
            return StreamSplitter::SEARCH;
        }
        else
        {
            *fp = ssh_len;
            return StreamSplitter::FLUSH;
        }
    }
    else
    {
        remain_bytes = remain_bytes - len;
        if (!remain_bytes)
        {
            *fp = len;
            return StreamSplitter::FLUSH;
        }
        else
        {
            return StreamSplitter::SEARCH;
        }
    }
}

StreamSplitter::Status SshSplitter::ssh2_scan(SSHData* sessp,
    const uint8_t* data, uint32_t len, uint32_t flags, uint32_t* fp)
{
    if (flags & PKT_FROM_SERVER)
    {
        // Do not scan if server new keys message seen.
        if (sessp->state_flags & SSH_FLG_SERVER_NEWKEYS_SEEN)
        {
            return SEARCH;
        }

        return ssh2_key_exchange_scan(data, len, fp, server_remain_bytes);
    }
    else
    {
        return ssh2_key_exchange_scan(data, len, fp, client_remain_bytes);
    }
}

StreamSplitter::Status SshSplitter::scan(
    Packet* p, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    Flow* flow = p->flow;
    SSHData* sessp = get_session_data(flow);

    if (sessp and sessp->ssh_aborted)
    {
        sshstats.aborted_sessions++;
        return ABORT;
    }

    if (nullptr == sessp)
    {
        sessp  = SetNewSSHData(p);
        if (nullptr == sessp)
            return ABORT;
    }

    if (sessp->state_flags & SSH_FLG_SESS_ENCRYPTED)
    {
        state = SSH_PAF_ENCRYPTED;
    }
    else if (((flags & PKT_FROM_SERVER)
        and (sessp->state_flags & SSH_FLG_SERV_IDSTRING_SEEN))
        or ((flags & PKT_FROM_CLIENT)
        and (sessp->state_flags & SSH_FLG_CLIENT_IDSTRING_SEEN)))
    {
        state = SSH_PAF_KEY_EXCHANGE;
    }
    else if (!(isprint(data[0]) or isspace(data[0])))
    {
        sessp->state_flags |= SSH_FLG_MISSED_PACKETS;
        state = SSH_PAF_ENCRYPTED;
    }

    switch (state)
    {
    case SSH_PAF_VER_EXCHANGE:
    {
        const uint8_t *lf = (const uint8_t*)memchr(data, '\n', len);
        if (lf)
        {
            *fp = lf - data + 1;
            return FLUSH;
        }
        return SEARCH;
    }
    case SSH_PAF_KEY_EXCHANGE:
    {
        if (sessp->version == SSH_VERSION_2)
        {
            return ssh2_scan(sessp, data, len, flags, fp);
        }
    }
    // fallthrough
    default:
    {
        // there will not be multiple SSH payloads in single TCP PDU.
        // for SSH1 or Encrypted PDUs flush it at data boundary.
        *fp = len;
        return FLUSH;
    }
    }
}

