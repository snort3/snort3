//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detection_filter.h"

#include "hash/xhash.h"
#include "log/messages.h"
#include "utils/util.h"

#include "sfthd.h"

using namespace snort;

THREAD_LOCAL ProfileStats snort::detectionFilterPerfStats;

XHash* detection_filter_hash = nullptr;

DetectionFilterConfig* DetectionFilterConfigNew()
{
    DetectionFilterConfig* df =
        (DetectionFilterConfig*)snort_calloc(sizeof(DetectionFilterConfig));

    df->memcap = 1024 * 1024;
    df->enabled = 1;

    return df;
}

void DetectionFilterConfigFree(DetectionFilterConfig* config)
{
    if (config == nullptr)
        return;

    snort_free(config);
}

int detection_filter_test(void* pv, const SfIp* sip, const SfIp* dip, long curtime)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(detectionFilterPerfStats);

    if (pv == nullptr)
        return 0;

    return sfthd_test_rule(detection_filter_hash, (THD_NODE*)pv,
        sip, dip, curtime, get_ips_policy()->policy_id);
}

THD_NODE* detection_filter_create(DetectionFilterConfig* df_config, THDX_STRUCT* thdx)
{
    if (df_config == nullptr)
        return nullptr;

    if (!df_config->enabled)
        return nullptr;

    df_config->count++;

    return sfthd_create_rule_threshold(df_config->count, thdx->tracking,
        thdx->type, thdx->count, thdx->seconds);
}

void detection_filter_init(DetectionFilterConfig* df_config)
{
    if ( !df_config->enabled )
        return;

    if ( !detection_filter_hash )
        detection_filter_hash = sfthd_local_new(df_config->memcap);
}

void detection_filter_term()
{
    if ( !detection_filter_hash )
        return;

    delete detection_filter_hash;
    detection_filter_hash = nullptr;
}

