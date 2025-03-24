//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdint>

namespace snort
{
struct Packet;
}

/* actions */
#define ACTION_NOTHING               0x00000000
#define ACTION_RST                   0x00000001
#define ACTION_BAD_PKT               0x00000002
#define ACTION_LWSSN_CLOSED          0x00000004
#define ACTION_DISABLE_INSPECTION    0x00000008

#define TF_NONE             0x0000
#define TF_WSCALE           0x0001
#define TF_TSTAMP           0x0002
#define TF_TSTAMP_ZERO      0x0004
#define TF_MSS              0x0008
#define TF_FORCE_FLUSH      0x0010
#define TF_PKT_MISSED       0x0020  // sticky
#define TF_MISSING_PKT      0x0040  // used internally
#define TF_MISSING_PREV_PKT 0x0080  // reset for each reassembled

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

#define STREAM_DEFAULT_MAX_SMALL_SEG_SIZE 0    /* disabled */
#define STREAM_DEFAULT_CONSEC_SMALL_SEGS 0     /* disabled */

#define SLAM_MAX 4

#define MAX_ZERO_WIN_PROBE_LEN 1
#define MAX_KEEP_ALIVE_PROBE_LEN 1

// The normalizer policy options FIRST thru VISTA are user configurable normalizer polices and this sequence
// must match with the configuration strings defined by TCP_POLICIES in stream.h.  The normalizer policy types 
// defined after VISTA are determined dynamically and assigned to a flow when appropriate, they are not configurable.
namespace Normalizer
{
    enum Policy : uint8_t
    {
        FIRST = 0,
        LAST,
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
        PROXY,
        MISSED_3WHS,
        MAX_NORM_POLICY,
        DEFAULT = OS_BSD
    };
}

// increment operator...
inline Normalizer::Policy& operator++(Normalizer::Policy& c, int)
{
    if ( c < Normalizer::Policy::MAX_NORM_POLICY )
        c = static_cast<Normalizer::Policy>( static_cast<int>(c) + 1 );
    else
        c = Normalizer::Policy::MAX_NORM_POLICY;

    return c;
}

// The overlap policy options FIRST thru VISTA are user configurable normalizer polices and this sequence
// must match with the configuration strings defined by TCP_POLICIES in stream.h.  Note that the FIRST overlap
// policy is configurable but is also the policy used for all flows when stream is configured to be in IPS mode.
namespace Overlap
{
    enum Policy : uint8_t
    {
        FIRST = 0,
        LAST,
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
        MAX_OVERLAP_POLICY,
        DEFAULT_POLICY = OS_BSD
    };
}

// increment operator...
inline Overlap::Policy& operator++(Overlap::Policy& c, int)
{
    if ( c < Overlap::Policy::MAX_OVERLAP_POLICY )
        c = static_cast<Overlap::Policy>( static_cast<int>(c) + 1 );
    else
        c = Overlap::Policy::MAX_OVERLAP_POLICY;

    return c;
}

enum FlushPolicy
{
    STREAM_FLPOLICY_IGNORE, /* ignore this traffic */
    STREAM_FLPOLICY_ON_ACK, /* protocol aware flushing (PAF) */
    STREAM_FLPOLICY_ON_DATA, /* protocol aware ips */
};

#endif

