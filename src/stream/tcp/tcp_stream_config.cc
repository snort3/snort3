//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// tcp_stream_config.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Oct 22, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_stream_config.h"

#include "log/messages.h"

using namespace snort;

static const char* const reassembly_policy_names[] =
{ "no policy", "first", "last", "linux", "old_linux", "bsd", "macos", "solaris", "irix",
  "hpux11", "hpux10", "windows", "win_2003", "vista", "proxy" };

TcpStreamConfig::TcpStreamConfig() = default;

void TcpStreamConfig::show_config()
{
    TcpStreamConfig::show_config(this);
}

void TcpStreamConfig::show_config(TcpStreamConfig* config)
{
    LogMessage("Stream TCP Policy config:\n");
    LogMessage("    Reassembly Policy: %s\n",
        reassembly_policy_names[ static_cast<int>( config->reassembly_policy ) ]);
    LogMessage("    Timeout: %d seconds\n", config->session_timeout);

    if ( config->max_window != 0 )
        LogMessage("    Max TCP Window: %u\n", config->max_window);

    if ( config->overlap_limit )
        LogMessage("    Limit on TCP Overlaps: %d\n", config->overlap_limit);

    if ( config->max_queued_bytes != 0 )
        LogMessage("    Maximum number of bytes to queue per session: %d\n",
            config->max_queued_bytes);

    if ( config->max_queued_segs != 0 )
        LogMessage("    Maximum number of segs to queue per session: %d\n",
            config->max_queued_segs);

    if ( config->flags )
    {
        LogMessage("    Options:\n");
        if (config->flags & STREAM_CONFIG_NO_ASYNC_REASSEMBLY)
            LogMessage("        Don't queue packets on one-sided sessions: YES\n");
    }

    if ( config->hs_timeout < 0 )
        LogMessage("    Require 3-Way Handshake: NO\n");
    else
        LogMessage("    Require 3-Way Handshake: after %d seconds\n", config->hs_timeout);
}

