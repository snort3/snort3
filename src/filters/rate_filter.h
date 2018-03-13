//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

// rate_filter.h author Dilbagh Chahal <dchahal@sourcefire.com>

#ifndef RATE_FILTER_H
#define RATE_FILTER_H

// rate filter interface for Snort
namespace snort
{
struct Packet;
struct SnortConfig;
}
struct RateFilterConfig;
struct tSFRFConfigNode;
struct OptTreeNode;

RateFilterConfig* RateFilter_ConfigNew();
void RateFilter_ConfigFree(RateFilterConfig*);
void RateFilter_Cleanup();

int RateFilter_Create(snort::SnortConfig* sc, RateFilterConfig*, tSFRFConfigNode*);
void RateFilter_PrintConfig(RateFilterConfig*);

int RateFilter_Test(const OptTreeNode*, snort::Packet*);

#endif

