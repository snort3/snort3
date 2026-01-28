//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// trace_loader.h author Pranav Jain <ppramodj@cisco.com>

#ifndef TRACE_LOADER_H
#define TRACE_LOADER_H

#include "protocols/packet.h"
#include "utils/util.h"
#include <string>

void load_trace();
std::string g_timestamp(bool timestamp);
std::string g_ntuple(bool ntuple, const snort::Packet* p);
char get_current_thread_type();

#endif

