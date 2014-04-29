/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "stream_global.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>

#include "packet_io/active.h"
#include "parser/mstring.h"

//-------------------------------------------------------------------------
// default limits
//-------------------------------------------------------------------------

#define S5_RIDICULOUS_HI_MEMCAP  1024*1024*1024 /* 1GB */
#define S5_RIDICULOUS_LOW_MEMCAP 32768    /* 32k*/
#define S5_RIDICULOUS_MAX_SESSIONS 1024*1024 /* 1 million sessions */

#define S5_MAX_CACHE_TIMEOUT                    (12 * 60 * 60)  /* 12 hours */
#define S5_MIN_PRUNE_LOG_MAX     1024      /* 1k packet data stored */
#define S5_MAX_PRUNE_LOG_MAX     S5_RIDICULOUS_HI_MEMCAP  /* 1GB packet data stored */

#define S5_DEFAULT_PRUNE_LOG_MAX 1048576  /* 1MB */

#define S5_DEFAULT_MAX_ACTIVE_RESPONSES  0   /* default to no responses */
#define S5_DEFAULT_MIN_RESPONSE_SECONDS  1   /* wait at least 1 second between resps */

#define S5_MAX_ACTIVE_RESPONSES_MAX      25  /* banging your head against the wall */
#define S5_MIN_RESPONSE_SECONDS_MAX      300 /* we want to stop the flow soonest */

//-------------------------------------------------------------------------
// global stuff
//-------------------------------------------------------------------------

#if 0 // FIXIT do this in configure:
        else if(!strcasecmp(stoks[0], "max_active_responses"))
        {
            if ( config->max_active_responses > 0 )
            {
                Active_SetEnabled(2);
            }
        }

    // FIXIT do this if any max_sessions > 0:
    sc->run_flags |= RUN_FLAG__STATEFUL;
#endif

//-------------------------------------------------------------------------
// public stuff
//-------------------------------------------------------------------------

void Stream5ConfigGlobal(
    Stream5Config* config, SnortConfig*, char*)
{
    Stream5GlobalConfig* pc = config->global_config;

    if ( pc )
    {
        ParseError("stream5_global can only be configred once per policy");
        return;
    }
    pc = (Stream5GlobalConfig*)SnortAlloc(sizeof(*pc));
    config->global_config = pc;

    pc->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;
    pc->max_active_responses = S5_DEFAULT_MAX_ACTIVE_RESPONSES;
    pc->min_response_seconds = S5_DEFAULT_MIN_RESPONSE_SECONDS;

    get_inspection_policy()->s5_config = config;
}

void Stream5PrintGlobalConfig(Stream5Config* s5)
{
    Stream5GlobalConfig* config = s5->global_config;

    LogMessage("Stream5 global config:\n");
    LogMessage("Max TCP sessions: %u\n", config->max_tcp_sessions);

    if ( config->max_tcp_sessions )
    {
        LogMessage("    TCP cache pruning timeout: %u seconds\n", config->tcp_cache_pruning_timeout);
        LogMessage("    TCP cache nominal timeout: %u seconds\n", config->tcp_cache_nominal_timeout);
        LogMessage("    Memcap (for reassembly packet storage): " STDu64 "\n",
            config->tcp_mem_cap);
    }
    LogMessage("Max UDP sessions: %u\n", config->max_udp_sessions);
    if (config->max_udp_sessions == S5_TRACK_YES)
    {
        LogMessage("    UDP cache pruning timeout: %u seconds\n", config->udp_cache_pruning_timeout);
        LogMessage("    UDP cache nominal timeout: %u seconds\n", config->udp_cache_nominal_timeout);
    }
    LogMessage("Max ICMP sessions: %u\n", config->max_icmp_sessions);
    LogMessage("Max IP sessions: %u\n", config->max_ip_sessions);

    if (config->prune_log_max)
    {
        LogMessage("    Log info if session memory consumption exceeds %d\n",
            config->prune_log_max);
    }
    LogMessage("    Send up to %d active responses\n",
        config->max_active_responses);

    if (config->max_active_responses > 1)
    {
        LogMessage("    Wait at least %d seconds between responses\n",
            config->min_response_seconds);
    }
    LogMessage("Maximum Flush Point: %u\n", ScPafMax());
#if 0
    // FIXIT need global->enable_ha?
#ifdef ENABLE_HA
    LogMessage("    High Availability: %s\n",
        config->ha_config ? "ENABLED" : "DISABLED");
#endif
#endif
#ifdef REG_TEST
    LogMessage("    Stream5LW Session Size: %lu\n",sizeof(Flow));
#endif
}

