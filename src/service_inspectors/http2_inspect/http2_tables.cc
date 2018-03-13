//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_tables.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/counts.h"

#include "http2_enum.h"
#include "http2_module.h"

using namespace Http2Enums;

const snort::RuleMap Http2Module::http2_events[] =
{
    { 0, nullptr }
};

const PegInfo Http2Module::peg_names[PEG_COUNT_MAX+1] =
{
    { CountType::SUM, "flows", "HTTP connections inspected" },
    { CountType::NOW, "concurrent_sessions", "total concurrent HTTP/2 sessions" },
    { CountType::MAX, "max_concurrent_sessions", "maximum concurrent HTTP/2 sessions" },
    { CountType::END, nullptr, nullptr }
};

