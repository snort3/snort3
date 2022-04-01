//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

// rate_filter.cc author Dilbagh Chahal <dchahal@sourcefire.com>
// rate filter interface for Snort

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rate_filter.h"

#include "detection/ips_context.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "hash/ghash.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "sfrf.h"

using namespace snort;

RateFilterConfig* RateFilter_ConfigNew()
{
    RateFilterConfig* rf_config = (RateFilterConfig*)snort_calloc(sizeof(*rf_config));
    rf_config->memcap = 1024 * 1024;
    return rf_config;
}

void RateFilter_ConfigFree(RateFilterConfig* config)
{
    int i;

    if (config == nullptr)
        return;

    for (i = 0; i < SFRF_MAX_GENID; i++)
    {
        if ( config->genHash[i] )
            delete config->genHash[i];
    }

    snort_free(config);
}

void RateFilter_Cleanup()
{
    SFRF_Delete();
}

/*
 * Create and Add a Thresholding Event Object
 */
int RateFilter_Create(
    SnortConfig* sc, RateFilterConfig* rf_config, tSFRFConfigNode* thdx)
{
    int error;

    if (rf_config == nullptr)
        return -1;

#ifdef RF_DBG
    printf(
        "THRESHOLD: gid=%u, sid=%u, tracking=%d, count=%u, seconds=%u \n",
        thdx->gid, thdx->sid, thdx->tracking, thdx->count, thdx->seconds);
#endif

    /* Add the object to the table - */
    error = SFRF_ConfigAdd(sc, rf_config, thdx);

    // enable internal events as required
    if ( !error && EventIsInternal(thdx->gid) )
    {
        enable_internal_event(rf_config, thdx->sid);

        if ( thdx->sid == SESSION_EVENT_SETUP )
            enable_internal_event(rf_config, SESSION_EVENT_CLEAR);
    }
    return error;
}

/*
    Test an event against the threshold object table
    to determine if the new_action should be applied.

    returns 1 - rate threshold reached
            0 - rate threshold not reached
*/
int RateFilter_Test(const OptTreeNode* otn, Packet* p)
{
    unsigned gid = otn->sigInfo.gid;
    unsigned sid = otn->sigInfo.sid;

    const SfIp* sip;
    const SfIp* dip;
    SfIp cleared;

    if ( p->has_ip_hdr() )
    {
        sip = p->ptrs.ip_api.get_src();
        dip = p->ptrs.ip_api.get_dst();
    }
    else
    {
        cleared.clear();
        sip = &cleared;
        dip = &cleared;
    }

    RateFilterConfig* rfc = p->context->conf->rate_filter_config;

    if ( EventIsInternal(gid) )
    {
        // at present stream connection events are the only internal
        // events and these require: src -> client, dst -> server.
        if ( p->is_from_server() )
        {
            return SFRF_TestThreshold(rfc, gid, sid, get_inspection_policy()->policy_id,
                dip, sip, p->pkth->ts.tv_sec, SFRF_COUNT_INCREMENT);
        }
    }

    return SFRF_TestThreshold(rfc, gid, sid, get_inspection_policy()->policy_id,
        sip, dip, p->pkth->ts.tv_sec, SFRF_COUNT_INCREMENT);
}

