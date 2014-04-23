/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2012-2013 Sourcefire, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/

/**************************************************************************
 *
 * stream_ha.h
 *
 * Authors: Michael Altizer <maltizer@sourcefire.com>, Russ Combs <rcombs@sourcefire.com>
 *
 * Description:
 *
 * Stream5 high availability exported functionality.
 *
 **************************************************************************/

#ifndef STREAM5_HA_H
#define STREAM5_HA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_HA
#include "snort_types.h"
#include "stream_common.h"

struct Stream5HaConfig
{
    char enable_ha;
    char *startup_input_file;
    char *runtime_output_file;
    char *shutdown_output_file;
# ifdef SIDE_CHANNEL
    uint8_t use_side_channel;
# endif
    struct timeval min_session_lifetime;
    struct timeval min_sync_interval;
};

typedef enum
{
    HA_EVENT_UPDATE,
    HA_EVENT_DELETE,
    HA_EVENT_MAX
} HA_Event;

typedef Flow *(*f_ha_create_session) (const FlowKey *);
typedef void (*f_ha_delete_session) (const FlowKey *);
typedef Flow *(*f_ha_get_lws) (const FlowKey *);
typedef void (*f_ha_deactivate_session) (Flow *);

typedef struct
{
    f_ha_get_lws get_lws;

    f_ha_create_session create_session;
    f_ha_deactivate_session deactivate_session;
    f_ha_delete_session delete_session;
} HA_Api;

int ha_set_api(unsigned proto, const HA_Api *);

#define HA_CRITICAL_SESSION_FLAGS  \
    (SSNFLAG_DROP_CLIENT | SSNFLAG_DROP_SERVER | SSNFLAG_RESET)

// Used with HA_State.ha_flags:
#define HA_FLAG_STANDBY         0x01    // session is not active
#define HA_FLAG_NEW             0x02    // flow has never been synchronized
#define HA_FLAG_MODIFIED        0x04    // session HA state information has been modified
#define HA_FLAG_MAJOR_CHANGE    0x08    // session HA state information has been modified in a major fashion
#define HA_FLAG_CRITICAL_CHANGE 0x10    // session HA state information has been modified in a critical fashion
#define HA_FLAG_DELETED         0x20    // flow deletion message has been sent

int RegisterStreamHAFuncs(uint32_t preproc_id, uint8_t subcode, uint8_t size,
                            StreamHAProducerFunc produce, StreamHAConsumerFunc consume);
void UnregisterStreamHAFuncs(uint32_t preproc_id, uint8_t subcode);
void Stream5SetHAPendingBit(void *flow, int bit);

void Stream5CleanHA(void);
void Stream5ProcessHA(Stream5HaConfig*, Flow*);
void Stream5HANotifyDeletion(Stream5HaConfig*, Flow *lwssn);

Stream5HaConfig* Stream5ConfigHa(SnortConfig*, char *args);

void ha_sinit();
void ha_term(Stream5HaConfig*);
void ha_setup(Stream5HaConfig*);
void ha_stats();
void ha_show(Stream5HaConfig*);
void ha_reset_stats();
void ha_reset(Flow*);

static inline bool ha_is_standby(const Flow* flow)
{
    return ( flow->ha_state && flow->ha_state->ha_flags & HA_FLAG_STANDBY );
}

static inline void ha_notify_deletion(Flow* flow)
{
    if ( !flow->ha_state )
        return;

    Stream5HaConfig* ha_config = flow->s5_config->ha_config;

    if ( !ha_config )
        return;

    Stream5HANotifyDeletion(ha_config, flow);

    flow->ha_state->ha_flags |=
        (HA_FLAG_NEW | HA_FLAG_MODIFIED | HA_FLAG_MAJOR_CHANGE);
}

static inline void ha_change_direction(Flow* flow)
{
    if ( !flow->ha_state )
        return;

    flow->ha_state->ha_flags |= HA_FLAG_MODIFIED;

    if ( flow->s5_state.ignore_direction == SSN_DIR_BOTH )
        flow->ha_state->ha_flags |= HA_FLAG_CRITICAL_CHANGE;
}

static inline void ha_modify(Flow* flow)
{
    if ( flow->ha_state )
        flow->ha_state->ha_flags |= HA_FLAG_MODIFIED;
}

static inline void ha_critical(Flow* flow)
{
    if ( flow->ha_state )
        flow->ha_state->ha_flags |= HA_FLAG_MODIFIED | HA_FLAG_CRITICAL_CHANGE;
}

static inline void ha_process(Flow* flow)
{
    if ( !flow || !flow->ha_state )
        return;

    if ( !flow->ha_state->ha_pending_mask && !(flow->ha_state->ha_flags & HA_FLAG_MODIFIED) )
        return;

    Stream5HaConfig* ha_config = flow->s5_config->ha_config;

    if ( !ha_config )
        return;

    Stream5ProcessHA(ha_config, flow);
}

static inline void ha_pending(Flow* flow, unsigned int ha_func_idx)
{
     flow->ha_state->ha_pending_mask |= (1 << ha_func_idx);
}

void ha_state_diff(Flow*, const Stream5State*);
void ha_update_flags(Flow*, uint32_t flags);
#else
#define ha_is_standby(flow) false
#define ha_notify_deletion(flow)
#define ha_state_diff(flow, state)
#define ha_change_direction(flow)
#define ha_modify(flow)
#define ha_critical(flow)
#define ha_update_flags(flow, flags)
#define ha_process(flow)
#define ha_pending(flow, ha_func_idx)
#endif /* ENABLE_HA */

#endif /* STREAM5_HA_H */
