//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_defs.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_DEFS_H
#define TCP_DEFS_H

#include "main/snort_debug.h"

/* TCP states */
#define TCP_STATE_NONE         0
#define TCP_STATE_LISTEN       1
#define TCP_STATE_SYN_RCVD     2
#define TCP_STATE_SYN_SENT     3
#define TCP_STATE_ESTABLISHED  4
#define TCP_STATE_CLOSE_WAIT   5
#define TCP_STATE_LAST_ACK     6
#define TCP_STATE_FIN_WAIT_1   7
#define TCP_STATE_CLOSING      8
#define TCP_STATE_FIN_WAIT_2   9
#define TCP_STATE_TIME_WAIT   10
#define TCP_STATE_CLOSED      11

/* actions */
#define ACTION_NOTHING                  0x00000000
#define ACTION_FLUSH_SENDER_STREAM      0x00000001
#define ACTION_FLUSH_RECEIVER_STREAM    0x00000002
#define ACTION_DROP_SESSION             0x00000004
#define ACTION_ACK_SENDER_DATA          0x00000008
#define ACTION_ACK_RECEIVER_DATA        0x00000010
#define ACTION_SET_SSN                  0x00000040
#define ACTION_COMPLETE_TWH             0x00000080
#define ACTION_RST                      0x00000100
#define ACTION_BAD_SEQ                  0x00000200
#define ACTION_BAD_PKT                  0x00000400
#define ACTION_LWSSN_CLOSED             0x00000800
#define ACTION_DISABLE_INSPECTION       0x00001000


#define TF_NONE                     0x0000
#define TF_WSCALE                   0x0001
#define TF_TSTAMP                   0x0002
#define TF_TSTAMP_ZERO              0x0004
#define TF_MSS                      0x0008
#define TF_FORCE_FLUSH              0x0010
#define TF_PKT_MISSED               0x0020  // sticky
#define TF_MISSING_PKT              0x0040  // used internally
#define TF_MISSING_PREV_PKT         0x0080  // reset for each reassembled
#define TF_FIRST_PKT_MISSING        0x0100

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

#define SUB_SYN_SENT  0x01
#define SUB_ACK_SENT  0x02
#define SUB_SETUP_OK  0x03
#define SUB_RST_SENT  0x04
#define SUB_FIN_SENT  0x08

// reassembly definitions... FIXIT - move to reassembly class when we get there
#define STREAM_INSERT_OK            0
#define STREAM_INSERT_ANOMALY       1
#define STREAM_INSERT_TIMEOUT       2
#define STREAM_INSERT_FAILED        3

#define REASSEMBLY_POLICY_FIRST       1
#define REASSEMBLY_POLICY_LAST        2
#define REASSEMBLY_POLICY_LINUX       3
#define REASSEMBLY_POLICY_OLD_LINUX   4
#define REASSEMBLY_POLICY_BSD         5
#define REASSEMBLY_POLICY_MACOS       6
#define REASSEMBLY_POLICY_SOLARIS     7
#define REASSEMBLY_POLICY_IRIX        8
#define REASSEMBLY_POLICY_HPUX11      9
#define REASSEMBLY_POLICY_HPUX10     10
#define REASSEMBLY_POLICY_WINDOWS    11
#define REASSEMBLY_POLICY_WINDOWS2K3 12
#define REASSEMBLY_POLICY_VISTA      13
#define REASSEMBLY_POLICY_DEFAULT    REASSEMBLY_POLICY_BSD

struct TcpDataBlock
{
    uint32_t seq;
    uint32_t ack;
    uint32_t win;
    uint32_t end_seq;
    uint32_t ts;
};


//#define DEBUG_STREAM_EX
#ifdef DEBUG_STREAM_EX
#define STREAM_DEBUG_WRAP(x) DEBUG_WRAP(x)
#else
#define STREAM_DEBUG_WRAP(x)
#endif

#endif
