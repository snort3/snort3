//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef DETECTION_FILTER_H
#define DETECTION_FILTER_H

// the use of threshold standalone, in config, and in rules is deprecated.
// - standalone and config are replaced with event_filter.
// - within a rule is replaced with detection_filter.
//
// both detection_filter and event_filter use the same basic mechanism.
// however, detection_filter is evaluated as the final step in rule matching.
// and thereby controls event generation.  event_filter is evaluated after
// the event is queued, and thereby controls which events get logged.

namespace snort
{
struct SfIp;
}

struct DetectionFilterConfig
{
    int count;
    int memcap;
    int enabled;
};

DetectionFilterConfig* DetectionFilterConfigNew();
void DetectionFilterConfigFree(DetectionFilterConfig*);

void detection_filter_init(DetectionFilterConfig*);
void detection_filter_term();

void detection_filter_print_config(DetectionFilterConfig*);

int detection_filter_test(void*, const snort::SfIp* sip, const snort::SfIp* dip, long curtime);
struct THD_NODE* detection_filter_create(DetectionFilterConfig*, struct THDX_STRUCT*);

#endif

