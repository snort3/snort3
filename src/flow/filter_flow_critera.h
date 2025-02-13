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

#ifndef FILTER_FLOW_CRITERIA_H
#define FILTER_FLOW_CRITERIA_H

#include <string>
#include "sfip/sf_ip.h"
#include <framework/decode_data.h>

struct FilterFlowCriteria
{
	PktType pkt_type;
    snort::SfIp source_sfip;
    snort::SfIp destination_sfip;
	uint16_t source_port = 0;
	uint16_t destination_port = 0;
    snort::SfIp source_subnet_sfip;
    snort::SfIp destination_subnet_sfip;
};
#endif
