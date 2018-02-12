//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// ssh_config.h author Chris Sherwin

#ifndef SSH_CONFIG_H
#define SSH_CONFIG_H

// Configuration for SSH service inspector

struct SSH_PROTO_CONF
{
    uint16_t MaxEncryptedPackets;
    uint16_t MaxClientBytes;
    uint16_t MaxServerVersionLen;
};

struct SshStats
{
    PegCount total_packets;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
};

#endif
