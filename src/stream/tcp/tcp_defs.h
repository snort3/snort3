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

// tcp_defs.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_DEFS_H
#define TCP_DEFS_H

#include "main/thread.h"

namespace snort
{
struct Packet;
}

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

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

#define SUB_STATE_NONE 0x00
#define SUB_SYN_SENT  0x01
#define SUB_ACK_SENT  0x02
#define SUB_SETUP_OK  0x03
#define SUB_RST_SENT  0x04
#define SUB_FIN_SENT  0x08

#define STREAM_UNALIGNED       0
#define STREAM_ALIGNED         1

#define STREAM_DEFAULT_MAX_QUEUED_BYTES 1048576 /* 1 MB */
#define AVG_PKT_SIZE            400
#define STREAM_DEFAULT_MAX_QUEUED_SEGS ( STREAM_DEFAULT_MAX_QUEUED_BYTES / AVG_PKT_SIZE )

#define STREAM_DEFAULT_MAX_SMALL_SEG_SIZE 0    /* disabled */
#define STREAM_DEFAULT_CONSEC_SMALL_SEGS 0     /* disabled */

#define SLAM_MAX 4

// target-based policy types - changes to this enum require changes to stream.h::TCP_POLICIES
enum class StreamPolicy
{
    OS_INVALID = 0,
    OS_FIRST,
    OS_LAST,
    OS_LINUX,
    OS_OLD_LINUX,
    OS_BSD,
    OS_MACOS,
    OS_SOLARIS,
    OS_IRIX,
    OS_HPUX11,
    OS_HPUX10,
    OS_WINDOWS,
    OS_WINDOWS2K3,
    OS_VISTA,
    OS_PROXY,
    OS_END_OF_LIST,
    OS_DEFAULT = OS_BSD
};

// increment operator...
inline StreamPolicy& operator++(StreamPolicy& c)
{
    if ( c < StreamPolicy::OS_END_OF_LIST )
        c = static_cast<StreamPolicy>( static_cast<int>(c) + 1 );
    else
        c = StreamPolicy::OS_END_OF_LIST;

    return c;
}

enum class ReassemblyPolicy
{
    OS_INVALID = 0,
    OS_FIRST,
    OS_LAST,
    OS_LINUX,
    OS_OLD_LINUX,
    OS_BSD,
    OS_MACOS,
    OS_SOLARIS,
    OS_IRIX,
    OS_HPUX11,
    OS_HPUX10,
    OS_WINDOWS,
    OS_WINDOWS2K3,
    OS_VISTA,
    OS_PROXY,
    OS_END_OF_LIST,
    OS_DEFAULT = OS_BSD
};

// increment operator...
inline ReassemblyPolicy& operator++(ReassemblyPolicy& c)
{
    if ( c < ReassemblyPolicy::OS_END_OF_LIST )
        c = static_cast<ReassemblyPolicy>( static_cast<int>(c) + 1 );
    else
        c = ReassemblyPolicy::OS_END_OF_LIST;

    return c;
}

enum FlushPolicy
{
    STREAM_FLPOLICY_IGNORE, /* ignore this traffic */
    STREAM_FLPOLICY_ON_ACK, /* protocol aware flushing (PAF) */
    STREAM_FLPOLICY_ON_DATA, /* protocol aware ips */
};

#endif

