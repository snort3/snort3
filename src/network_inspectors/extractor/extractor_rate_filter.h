//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// extractor_rate_filter.h author vhorbato@cisco.com

#ifndef EXTRACTOR_RATE_FILTER_H
#define EXTRACTOR_RATE_FILTER_H

#include <cstdint>
#include <ctime>

namespace snort
{
class Flow;
}

struct SamplingConfig
{
	uint32_t threshold = 25;
	uint32_t rate = 1000;
	uint32_t duration = 600;
};

namespace builtin
{
bool should_log(snort::Flow&, uint64_t binding_id, unsigned gid, unsigned sid, time_t now,
	const SamplingConfig&);
}

#endif
