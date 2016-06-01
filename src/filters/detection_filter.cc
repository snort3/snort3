//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "detection_filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/util.h"
#include "parser/parser.h"
#include "filters/sfthd.h"
#include "main/thread.h"

static THREAD_LOCAL SFXHASH* detection_filter_hash = NULL;

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
    if (config == NULL)
        return;

    snort_free(config);
}

void detection_filter_print_config(DetectionFilterConfig*)
{ }

int detection_filter_test(
    void* pv,
    const sfip_t* sip, const sfip_t* dip,
    long curtime)
{
    if (pv == NULL)
        return 0;

    return sfthd_test_rule(detection_filter_hash, (THD_NODE*)pv,
        sip, dip, curtime);
}

/* empty out active entries */
void detection_filter_reset_active()
{
    if (detection_filter_hash == NULL)
        return;

    sfxhash_make_empty(detection_filter_hash);
}

void* detection_filter_create(DetectionFilterConfig* df_config, THDX_STRUCT* thdx)
{
    if (df_config == NULL)
        return NULL;

    if (!df_config->enabled)
        return NULL;

    df_config->count++;

    return sfthd_create_rule_threshold(df_config->count, thdx->tracking,
        thdx->type, thdx->count, thdx->seconds);
}

void detection_filter_init(DetectionFilterConfig* df_config)
{
    if ( !df_config->enabled )
        return;

    if ( !detection_filter_hash )
    {
        detection_filter_hash = sfthd_local_new(df_config->memcap);

        if ( !detection_filter_hash )
            FatalError("can't allocate detection filter cache\n");
    }
}

void detection_filter_term()
{
    if ( !detection_filter_hash )
        return;

    sfxhash_delete(detection_filter_hash);
    detection_filter_hash = NULL;
}

