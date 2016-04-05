//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifndef STREAM_H
#define STREAM_H

#include <sys/types.h>
#include <netinet/in.h>

#include "main/snort_types.h"
#include "stream/stream_api.h"
#include "network_inspectors/normalize/norm.h"
#include "flow/session.h"

#define STREAM_DEFAULT_SSN_TIMEOUT  30        /* seconds to timeout a session */
#define STREAM_MAX_SSN_TIMEOUT      3600*24   /* max timeout (approx 1 day) */
#define STREAM_MIN_SSN_TIMEOUT      1         /* min timeout (1 second) */

#define STREAM_TRACK_YES            1
#define STREAM_TRACK_NO             0

// FIXIT-L move to proto specific where possible
#define STREAM_CONFIG_STATEFUL_INSPECTION      0x00000001
#define STREAM_CONFIG_LOG_STREAMS              0x00000004
#define STREAM_CONFIG_REASS_CLIENT             0x00000008
#define STREAM_CONFIG_REASS_SERVER             0x00000010
#define STREAM_CONFIG_ASYNC                    0x00000020
#define STREAM_CONFIG_SHOW_PACKETS             0x00000040
#define STREAM_CONFIG_MIDSTREAM_DROP_NOALERT   0x00000080
#define STREAM_CONFIG_IGNORE_ANY               0x00000100
#define STREAM_CONFIG_STATIC_FLUSHPOINTS       0x00000200
#define STREAM_CONFIG_IPS                      0x00000400
#define STREAM_CONFIG_NO_ASYNC_REASSEMBLY      0x00000800

// shared stream state
extern THREAD_LOCAL class FlowControl* flow_con;
extern const PegInfo base_pegs[];

const PegInfo* Stream_GetNormPegs();
NormPegs Stream_GetNormCounts(unsigned&);

#endif

