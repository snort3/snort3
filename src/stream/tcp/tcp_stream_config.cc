//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_config.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Oct 22, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_stream_config.h"

#include "log/messages.h"

using namespace snort;

static const char* const policy_names[] =
{ "first", "last", "linux", "old_linux", "bsd", "macos", "solaris", "irix",
  "hpux11", "hpux10", "windows", "win_2003", "vista", "proxy" };

TcpStreamConfig::TcpStreamConfig() = default;

void TcpStreamConfig::show() const
{
    ConfigLogger::log_value("flush_factor", flush_factor);
    ConfigLogger::log_value("max_pdu", paf_max);
    ConfigLogger::log_value("max_window", max_window);
    ConfigLogger::log_flag("no_ack", no_ack);
    ConfigLogger::log_value("overlap_limit", overlap_limit);
    ConfigLogger::log_value("policy", policy_names[static_cast<int>(policy)]);

    std::string str;
    str += "{ max_bytes = ";
    str += std::to_string(max_queued_bytes);
    str += ", max_segments = ";
    str += std::to_string(max_queued_segs);
    str += " }";
    ConfigLogger::log_value("queue_limit", str.c_str());

    ConfigLogger::log_flag("reassemble_async", !(flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY));
    ConfigLogger::log_limit("require_3whs", hs_timeout, -1, hs_timeout < 0 ? hs_timeout : -1);
    ConfigLogger::log_value("session_timeout", session_timeout);

    str = "{ count = ";
    str += std::to_string(max_consec_small_segs);
    str += ", maximum_size = ";
    str += std::to_string(max_consec_small_seg_size);
    str += " }";
    ConfigLogger::log_value("small_segments", str.c_str());

    ConfigLogger::log_flag("track_only", (flags & STREAM_CONFIG_NO_REASSEMBLY));
}

