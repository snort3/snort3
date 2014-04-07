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

static void Stream5ParseGlobalArgs(Stream5Config* s5, char *args)
{
    char **toks;
    int num_toks;
    int i;
    char **stoks;
    int s_toks;
    char *endPtr = NULL;
#define MAX_TCP 0x01
#define MAX_UDP 0x02
#define MAX_ICMP 0x04
#define MAX_IP 0x08
    char max_set = 0;

    if (s5 == NULL)
        return;

    if ((args == NULL) || (strlen(args) == 0))
        return;

    S5Common* common = s5->common;
    Stream5GlobalConfig* config = s5->global_config;

    toks = mSplit(args, ",", 0, &num_toks, 0);
    i = 0;

    for (i = 0; i < num_toks; i++)
    {
        stoks = mSplit(toks[i], " ", 4, &s_toks, 0);

        if (s_toks == 0)
        {
            ParseError("Missing parameter in Stream5 Global config.");
        }

        if(!strcasecmp(stoks[0], "memcap"))
        {
            if (stoks[1])
            {
                common->tcp_mem_cap = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid memcap in config file.  Requires integer parameter.");
            }

            if ((common->tcp_mem_cap > S5_RIDICULOUS_HI_MEMCAP) ||
                (common->tcp_mem_cap < S5_RIDICULOUS_LOW_MEMCAP))
            {
                ParseError("'memcap %s' invalid: value must be "
                           "between %d and %d bytes",
                           stoks[1], S5_RIDICULOUS_LOW_MEMCAP,
                           S5_RIDICULOUS_HI_MEMCAP);
            }
        }
        else if(!strcasecmp(stoks[0], "max_tcp"))
        {
            if (stoks[1])
            {
                common->max_tcp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ((common->max_tcp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (common->max_tcp_sessions == 0))
                    {
                        ParseError("'max_tcp %d' invalid: value must be "
                                   "between 1 and %d sessions",
                                   common->max_tcp_sessions,
                                   S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid max_tcp in config file.  Requires integer parameter.");
            }

            max_set |= MAX_TCP;
        }
        else if(!strcasecmp(stoks[0], "tcp_cache_pruning_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        ParseError(
                            "'%s %lu' invalid: value must be between 1 and %d seconds",
                            stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                common->tcp_cache_pruning_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid %s in config file.  Requires integer parameter.",
                           stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "tcp_cache_nominal_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_tcp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        ParseError(
                            "'%s %lu' invalid: value must be between 1 and %d seconds",
                            stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                common->tcp_cache_nominal_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid %s in config file.  Requires integer parameter.",
                           stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "track_tcp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_tcp_sessions = S5_TRACK_NO;
                else
                    config->track_tcp_sessions = S5_TRACK_YES;
            }
            else
            {
                ParseError("'track_tcp' missing option");
            }
        }
        else if(!strcasecmp(stoks[0], "max_udp"))
        {
            if (stoks[1])
            {
                common->max_udp_sessions = strtoul(stoks[1], &endPtr, 10);
                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ((common->max_udp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (common->max_udp_sessions == 0))
                    {
                        ParseError(
                            "'max_udp %d' invalid: value must be between 1 and %d sessions",
                            common->max_udp_sessions, S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid max_udp in config file.  Requires integer parameter.");
            }
            max_set |= MAX_UDP;
        }
        else if(!strcasecmp(stoks[0], "udp_cache_pruning_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        ParseError(
                            "'%s %lu' invalid: value must be between 1 and %d seconds",
                            stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                common->udp_cache_pruning_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid %s in config file.  Requires integer parameter.",
                           stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "udp_cache_nominal_timeout"))
        {
            if (stoks[1])
            {
                unsigned long timeout = strtoul(stoks[1], &endPtr, 10);

                if (config->track_udp_sessions == S5_TRACK_YES)
                {
                    if ( !timeout || (timeout > S5_MAX_CACHE_TIMEOUT) )
                    {
                        ParseError(
                            "'%s %lu' invalid: value must be between 1 and %d seconds",
                            stoks[0], timeout, S5_MAX_CACHE_TIMEOUT);
                    }
                }
                common->udp_cache_nominal_timeout = (uint16_t)timeout;
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid %s in config file.  Requires integer parameter.",
                           stoks[0]);
            }
        }
        else if(!strcasecmp(stoks[0], "track_udp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_udp_sessions = S5_TRACK_NO;
                else
                    config->track_udp_sessions = S5_TRACK_YES;
            }
            else
            {
                ParseError("'track_udp' missing option");
            }
        }
        else if(!strcasecmp(stoks[0], "max_icmp"))
        {
            if (stoks[1])
            {
                common->max_icmp_sessions = strtoul(stoks[1], &endPtr, 10);

                if (config->track_icmp_sessions == S5_TRACK_YES)
                {
                    if ((common->max_icmp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (common->max_icmp_sessions == 0))
                    {
                        ParseError(
                            "'max_icmp %d' invalid: value must be "
                            "between 1 and %d sessions",
                            common->max_icmp_sessions, S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid max_icmp in config file.  Requires integer parameter.");
            }
            max_set |= MAX_ICMP;
        }
        else if(!strcasecmp(stoks[0], "track_icmp"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_icmp_sessions = S5_TRACK_NO;
                else
                    config->track_icmp_sessions = S5_TRACK_YES;
            }
            else
            {
                ParseError("'track_icmp' missing option");
            }
        }
        else if(!strcasecmp(stoks[0], "max_ip"))
        {
            if (stoks[1])
            {
                common->max_ip_sessions = strtoul(stoks[1], &endPtr, 10);

                if (config->track_ip_sessions == S5_TRACK_YES)
                {
                    if ((common->max_ip_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                        (common->max_ip_sessions == 0))
                    {
                        ParseError(
                            "'max_ip %d' invalid: value must be "
                            "between 1 and %d sessions",
                            common->max_ip_sessions, S5_RIDICULOUS_MAX_SESSIONS);
                    }
                }
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid max_ip in config file.  Requires integer parameter.");
            }
            max_set |= MAX_IP;
        }
        else if(!strcasecmp(stoks[0], "track_ip"))
        {
            if (stoks[1])
            {
                if(!strcasecmp(stoks[1], "no"))
                    config->track_ip_sessions = S5_TRACK_NO;
                else
                    config->track_ip_sessions = S5_TRACK_YES;
            }
            else
            {
                ParseError("'track_ip' missing option");
            }
        }
        else if(!strcasecmp(stoks[0], "flush_on_alert"))
        {
            config->flags |= STREAM5_CONFIG_FLUSH_ON_ALERT;
        }
        else if(!strcasecmp(stoks[0], "show_rebuilt_packets"))
        {
            config->flags |= STREAM5_CONFIG_SHOW_PACKETS;
        }
        else if(!strcasecmp(stoks[0], "prune_log_max"))
        {
            if (stoks[1])
            {
                config->prune_log_max = strtoul(stoks[1], &endPtr, 10);
            }

            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid prune_log_max in config file.  "
                        "Requires integer parameter.");
            }

            if (((config->prune_log_max > S5_MAX_PRUNE_LOG_MAX) ||
                 (config->prune_log_max < S5_MIN_PRUNE_LOG_MAX)) &&
                (config->prune_log_max != 0))
            {
                ParseError(
                    "Invalid Prune Log Max.  Must be 0 (disabled) or between %d and %d",
                    S5_MIN_PRUNE_LOG_MAX, S5_MAX_PRUNE_LOG_MAX);
            }
        }
#ifdef TBD
        else if(!strcasecmp(stoks[0], "no_midstream_drop_alerts"))
        {
            /*
             * FIXTHIS: Do we want to not alert on drops for sessions picked
             * up midstream ?  If we're inline, and get a session midstream,
             * its because it was picked up during startup.  In inline
             * mode, we should ALWAYS be requiring TCP 3WHS.
             */
            config->flags |= STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT;
        }
#endif
        else if(!strcasecmp(stoks[0], "max_active_responses"))
        {
            if (stoks[1])
            {
                config->max_active_responses = (uint8_t)SnortStrtoulRange(stoks[1], &endPtr, 10, 0, S5_MAX_ACTIVE_RESPONSES_MAX);
            }
            if ((!stoks[1] || (endPtr == &stoks[1][0])) || (config->max_active_responses > S5_MAX_ACTIVE_RESPONSES_MAX))
            {
                ParseError("'max_active_responses %d' invalid: "
                    "value must be between 0 and %d responses.",
                    config->max_active_responses, S5_MAX_ACTIVE_RESPONSES_MAX);
            }
            if ( config->max_active_responses > 0 )
            {
                Active_SetEnabled(2);
            }
        }
        else if(!strcasecmp(stoks[0], "min_response_seconds"))
        {
            if (stoks[1])
            {
                config->min_response_seconds = strtoul(stoks[1], &endPtr, 10);
            }
            if (!stoks[1] || (endPtr == &stoks[1][0]))
            {
                ParseError("Invalid min_response_seconds in config file. "
                    " Requires integer parameter." );
            }
            else if (
                (config->min_response_seconds > S5_MIN_RESPONSE_SECONDS_MAX) ||
                (config->min_response_seconds < 1))
            {
                ParseError("'min_response_seconds %d' invalid: "
                    "value must be between 1 and %d seconds.",
                    config->min_response_seconds, S5_MIN_RESPONSE_SECONDS_MAX);
            }
        }
        else if(!strcasecmp(stoks[0], "disabled"))
        {
            config->disabled = 1;
        }
        else
        {
            ParseError("Unknown Stream5 global option (%s)", toks[i]);
        }

        mSplitFree(&stoks, s_toks);
    }

    mSplitFree(&toks, num_toks);
}

static void Stream5InitGlobal(
    Stream5Config* pc, SnortConfig* sc, char *args)
{
    Stream5ParseGlobalArgs(pc, args);

    if ((!pc->global_config->disabled) &&
        (pc->global_config->track_tcp_sessions == S5_TRACK_NO) &&
        (pc->global_config->track_udp_sessions == S5_TRACK_NO) &&
        (pc->global_config->track_icmp_sessions == S5_TRACK_NO) &&
        (pc->global_config->track_ip_sessions == S5_TRACK_NO))
    {
        ParseError("Stream5 enabled, but not configured to track "
                   "TCP, UDP, ICMP, or IP.");
    }

    sc->run_flags |= RUN_FLAG__STATEFUL;
}

//-------------------------------------------------------------------------
// public stuff
//-------------------------------------------------------------------------

void Stream5ConfigGlobal(
    Stream5Config* config, SnortConfig* sc, char *args)
{
    Stream5GlobalConfig* pc = config->global_config;

    if ( pc )
    {
        ParseError("stream5_global can only be configred once per policy");
        return;
    }
    pc = (Stream5GlobalConfig*)SnortAlloc(sizeof(*pc));
    config->global_config = pc;

    pc->track_tcp_sessions = S5_TRACK_YES;
    pc->track_udp_sessions = S5_TRACK_YES;
    pc->track_icmp_sessions = S5_TRACK_NO;
    pc->track_ip_sessions = S5_TRACK_NO;
    pc->prune_log_max = S5_DEFAULT_PRUNE_LOG_MAX;
    pc->max_active_responses = S5_DEFAULT_MAX_ACTIVE_RESPONSES;
    pc->min_response_seconds = S5_DEFAULT_MIN_RESPONSE_SECONDS;

    Stream5InitGlobal(config, sc, args);
    get_inspection_policy()->s5_config = config;
}

void Stream5PrintGlobalConfig(Stream5Config* s5)
{
    S5Common* common = s5->common;
    Stream5GlobalConfig* config = s5->global_config;

    LogMessage("Stream5 global config:\n");
    LogMessage("    Track TCP sessions: %s\n",
        config->track_tcp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_tcp_sessions == S5_TRACK_YES)
    {
        LogMessage("    Max TCP sessions: %u\n", common->max_tcp_sessions);
        LogMessage("    TCP cache pruning timeout: %u seconds\n", common->tcp_cache_pruning_timeout);
        LogMessage("    TCP cache nominal timeout: %u seconds\n", common->tcp_cache_nominal_timeout);
    }
    LogMessage("    Memcap (for reassembly packet storage): %d\n", common->tcp_mem_cap);
    LogMessage("    Track UDP sessions: %s\n",
        config->track_udp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_udp_sessions == S5_TRACK_YES)
    {
        LogMessage("    Max UDP sessions: %u\n", common->max_udp_sessions);
        LogMessage("    UDP cache pruning timeout: %u seconds\n", common->udp_cache_pruning_timeout);
        LogMessage("    UDP cache nominal timeout: %u seconds\n", common->udp_cache_nominal_timeout);
    }
    LogMessage("    Track ICMP sessions: %s\n",
        config->track_icmp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_icmp_sessions == S5_TRACK_YES)
        LogMessage("    Max ICMP sessions: %u\n",
            common->max_icmp_sessions);
    LogMessage("    Track IP sessions: %s\n",
        config->track_ip_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (config->track_ip_sessions == S5_TRACK_YES)
        LogMessage("    Max IP sessions: %u\n",
            common->max_ip_sessions);
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
    LogMessage("    Protocol Aware Flushing: %s\n",
        ScPafEnabled() ? "ACTIVE" : "INACTIVE");
    LogMessage("        Maximum Flush Point: %u\n", ScPafMax());
#if 0
    // FIXIT need global->enable_ha?
#ifdef ENABLE_HA
    LogMessage("    High Availability: %s\n",
        common->ha_config ? "ENABLED" : "DISABLED");
#endif
#endif
#ifdef REG_TEST
    LogMessage("    Stream5LW Session Size: %lu\n",sizeof(Flow));
#endif
}

