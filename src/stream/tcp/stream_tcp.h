//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#ifndef STREAM_TCP_H
#define STREAM_TCP_H

#include "flow/flow.h"
#include "stream/stream_api.h"
#include "protocols/packet.h"

#include "tcp_defs.h"
#include "tcp_stream_config.h"

// misc stuff
Session* get_tcp_session(Flow*);
TcpStreamConfig* get_tcp_cfg(Inspector*);

void tcp_sinit();
void tcp_sterm();
void tcp_sum();
void tcp_stats();
void tcp_reset_stats();
void tcp_show(TcpStreamConfig*);

#endif

