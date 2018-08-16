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

// ssh.h author Chris Sherwin

#ifndef SSH_H
#define SSH_H

// Implementation header with definitions, datatypes and flowdata class for
// SSH service inspector.

// Alert for Gobbles, CRC32, protocol mismatch (Cisco catalyst
// vulnerability), and a SecureCRT vulnerability.  Will also alert if the
// client or server traffic appears to flow the wrong direction, or if
// packets appear malformed/spoofed.

#include "flow/flow.h"

// FIXIT-L move these to ssh.cc
// Session state flags for SSHData::state_flags
#define SSH_FLG_CLEAR           (0x0)
#define SSH_FLG_CLIENT_IDSTRING_SEEN    (0x1)
#define SSH_FLG_SERV_IDSTRING_SEEN  (0x2)
#define SSH_FLG_SERV_PKEY_SEEN      (0x4)
#define SSH_FLG_CLIENT_SKEY_SEEN    (0x8)
#define SSH_FLG_CLIENT_KEXINIT_SEEN (0x10)
#define SSH_FLG_SERV_KEXINIT_SEEN   (0x20)
#define SSH_FLG_KEXDH_INIT_SEEN     (0x40)
#define SSH_FLG_KEXDH_REPLY_SEEN    (0x80)
#define SSH_FLG_GEX_REQ_SEEN        (0x100)
#define SSH_FLG_GEX_GRP_SEEN        (0x200)
#define SSH_FLG_GEX_INIT_SEEN       (0x400)
#define SSH_FLG_GEX_REPLY_SEEN      (0x800)
#define SSH_FLG_NEWKEYS_SEEN        (0x1000)
#define SSH_FLG_SESS_ENCRYPTED      (0x2000)
#define SSH_FLG_RESPOVERFLOW_ALERTED    (0x4000)
#define SSH_FLG_CRC32_ALERTED       (0x8000)
#define SSH_FLG_MISSED_PACKETS      (0x10000)
#define SSH_FLG_REASSEMBLY_SET      (0x20000)
#define SSH_FLG_AUTODETECTED        (0x40000)

// Some convenient combinations of state flags.
#define SSH_FLG_BOTH_IDSTRING_SEEN \
    (SSH_FLG_CLIENT_IDSTRING_SEEN |  \
    SSH_FLG_SERV_IDSTRING_SEEN )

#define SSH_FLG_V1_KEYEXCH_DONE \
    (SSH_FLG_SERV_PKEY_SEEN | \
    SSH_FLG_CLIENT_SKEY_SEEN )

#define SSH_FLG_V2_KEXINIT_DONE \
    (SSH_FLG_CLIENT_KEXINIT_SEEN | \
    SSH_FLG_SERV_KEXINIT_SEEN )

#define SSH_FLG_V2_DHOLD_DONE \
    (SSH_FLG_KEXDH_INIT_SEEN | \
    SSH_FLG_KEXDH_REPLY_SEEN | \
    SSH_FLG_NEWKEYS_SEEN )

#define SSH_FLG_V2_DHNEW_DONE \
    (SSH_FLG_GEX_REQ_SEEN | \
    SSH_FLG_GEX_GRP_SEEN | \
    SSH_FLG_GEX_INIT_SEEN | \
    SSH_FLG_GEX_REPLY_SEEN | \
    SSH_FLG_NEWKEYS_SEEN )

// SSH version values for SSHData::version
#define SSH_VERSION_UNKNOWN (0x0)
#define SSH_VERSION_1       (0x1)
#define SSH_VERSION_2       (0x2)

// Per-session data block containing current state
// of the SSH preprocessor for the session.
struct SSHData
{
    uint8_t version = SSH_VERSION_UNKNOWN; // Version of SSH detected for this session
    uint16_t num_enc_pkts;     // encrypted packets seen on this session
    uint16_t num_client_bytes; // bytes of encrypted data sent by client without a server response
    uint32_t state_flags;      // Bit vector describing the current state of the session
};

class SshFlowData : public snort::FlowData
{
public:
    SshFlowData();
    ~SshFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    SSHData session;
};

// Length of SSH2 header, in bytes.
#define SSH2_HEADERLEN      (5)
#define SSH2_PACKET_MAX_SIZE    (256 * 1024)

struct SSH2Packet
{
    uint32_t packet_length; // Length not including this field or the mesg auth code (mac)
    uint8_t padding_length; // Length of padding section.
    char packet_data[1];    // Variable length packet payload + padding + MAC.
};

// SSH v1 message types (of interest)
#define SSH_MSG_V1_SMSG_PUBLIC_KEY  2
#define SSH_MSG_V1_CMSG_SESSION_KEY 3

// SSH v2 message types (of interest)
#define SSH_MSG_KEXINIT     20
#define SSH_MSG_NEWKEYS     21
#define SSH_MSG_KEXDH_INIT  30
#define SSH_MSG_KEXDH_REPLY 31

#define SSH_MSG_KEXDH_GEX_REQ   34
#define SSH_MSG_KEXDH_GEX_GRP   33
#define SSH_MSG_KEXDH_GEX_INIT  32
#define SSH_MSG_KEXDH_GEX_REPLY 31

// Direction of sent message.
#define SSH_DIR_FROM_SERVER (0x1)
#define SSH_DIR_FROM_CLIENT (0x2)

#endif
