//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
/*
   sfthreshold.c

   This file contains functions that glue the generic thresholding2 code to
   snort.

   dependent files:  sfthd sfxghash ghash sflsq
                     util mstring

   Marc Norton

   2003-05-29:
     cmg: Added s_checked variable  --
       when this is 1, the sfthreshold_test will always return the same
       answer until
       sfthreshold_reset is called

   2003-11-3:
     man: cleaned up and added more startup printout.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfthreshold.h"

#include "hash/xhash.h"
#include "main/snort_config.h"
#include "utils/util.h"

#include "sfthd.h"

using namespace snort;

/* Data */
static THREAD_LOCAL THD_STRUCT* thd_runtime = nullptr;

static THREAD_LOCAL int thd_checked = 0; // per packet
static THREAD_LOCAL int thd_answer = 0;  // per packet

typedef enum { PRINT_GLOBAL, PRINT_LOCAL, PRINT_SUPPRESS } PrintFormat;

ThresholdConfig* ThresholdConfigNew()
{
    ThresholdConfig* tc =
        (ThresholdConfig*)snort_calloc(sizeof(ThresholdConfig));

    /* sfthd_objs_new will handle fatal */
    tc->thd_objs = sfthd_objs_new();
    tc->memcap = 1024 * 1024;
    tc->enabled = 1;

    return tc;
}

void ThresholdConfigFree(ThresholdConfig* tc)
{
    if (tc == nullptr)
        return;

    if (tc->thd_objs != nullptr)
    {
        sfthd_objs_free(tc->thd_objs);
        tc->thd_objs = nullptr;
    }

    snort_free(tc);
}

void sfthreshold_free()
{
    if (thd_runtime != nullptr)
        sfthd_free(thd_runtime);

    thd_runtime = nullptr;
}

int sfthreshold_alloc(unsigned int l_memcap, unsigned int g_memcap)
{
    if (thd_runtime == nullptr)
    {
        thd_runtime = sfthd_new(l_memcap, g_memcap);
        if (thd_runtime == nullptr)
            return -1;
    }
    return 0;
}


int sfthreshold_create(
    SnortConfig* sc, ThresholdConfig* thd_config, THDX_STRUCT* thdx, PolicyId policy_id)
{
    if (thd_config == nullptr)
        return -1;

    if (!thd_config->enabled)
        return 0;

    /* print_thdx( thdx ); */

    /* Add the object to the table - */
    return sfthd_create_threshold(sc,
        thd_config->thd_objs,
        thdx->gen_id,
        thdx->sig_id,
        thdx->tracking,
        thdx->type,
        thdx->priority,
        thdx->count,
        thdx->seconds,
        thdx->ip_address,
        policy_id);
}

/*
    Test an event against the threshold object table
    to determine if it should be logged.

    It will always return the same answer until sfthreshold_reset is
    called

    returns 0 - log
           !0 - don't log
*/
int sfthreshold_test(unsigned gen_id, unsigned sig_id, const SfIp* sip,
    const SfIp* dip, long curtime, PolicyId policy_id)
{
    if (!thd_checked)
    {
        thd_checked = 1;
        thd_answer = sfthd_test_threshold(SnortConfig::get_conf()->threshold_config->thd_objs,
            thd_runtime, gen_id, sig_id, sip, dip, curtime, policy_id);
    }

    return thd_answer;
}

/**
 * Reset the thresholding system so that subsequent calls to
 * sfthreshold_test will indeed try to alter the thresholding system
 *
 */
void sfthreshold_reset()
{
    thd_checked = 0;
}
