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

// @file    active.h
// @author  Russ Combs <rcombs@sourcefire.com>

#ifndef ACTIVE_H
#define ACTIVE_H

#include "decode.h"
#include "snort.h"
#include "encode.h"

int Active_Init(SnortConfig*);
int Active_Term(void);

typedef void (*Active_ResponseFunc)(Packet*, void* data);

int Active_QueueReject(void);
int Active_QueueResponse(Active_ResponseFunc, void*);
int Active_ResetQueue(void);

// this must be called on the wire packet and not a
// reassembled packet so that encoding is correct.
int Active_SendResponses(Packet*);
uint64_t Active_GetInjects(void);

// NULL flags implies ENC_FLAG_FWD
void Active_KillSession(Packet*, EncodeFlags*);

void Active_SendReset(Packet*, EncodeFlags);
void Active_SendUnreach(Packet*, EncodeType);
void Active_SendData(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);
void Active_InjectData(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);

int Active_IsRSTCandidate(const Packet*);
int Active_IsUNRCandidate(const Packet*);

int Active_IsEnabled(void);
void Active_SetEnabled(int on_off);

typedef enum {
    ACTIVE_ALLOW = 0,
    ACTIVE_DROP = 1,
    ACTIVE_WOULD_DROP = 2,
    ACTIVE_FORCE_DROP = 3
} tActiveDrop;

extern THREAD_LOCAL tActiveDrop active_drop_pkt;
extern THREAD_LOCAL int active_drop_ssn;
extern THREAD_LOCAL int active_have_rsp;
extern THREAD_LOCAL int active_tunnel_bypass;
extern THREAD_LOCAL int active_suspend;

static inline void Active_Reset (void)
{
    active_drop_pkt = ACTIVE_ALLOW;
    active_drop_ssn = 0;
    active_have_rsp = 0;
    active_tunnel_bypass = 0;
}

static inline void Active_Suspend (void)
{
    active_suspend = 1;
}

static inline void Active_Resume (void)
{
    active_suspend = 0;
}

static inline bool Active_Suspended (void)
{
    return ( active_suspend != 0 );
}

static inline void Active_ForceDropPacket (void)
{
    if ( Active_Suspended() )
        return;

    active_drop_pkt = ACTIVE_FORCE_DROP;
}

static inline void Active_DropPacket (void)
{
    if ( Active_Suspended() )
        return;

    if ( active_drop_pkt != ACTIVE_FORCE_DROP )
    {
        if ( ScInlineMode() )
        {
            active_drop_pkt = ACTIVE_DROP;
        }
        else if (ScInlineTestMode())
        {
            active_drop_pkt = ACTIVE_WOULD_DROP;
        }
    }
}

static inline void Active_DropSession (void)
{
    if ( Active_Suspended() )
        return;

    active_drop_ssn = 1;
    Active_DropPacket();
}

static inline void Active_ForceDropSession (void)
{
    if ( Active_Suspended() )
        return;

    active_drop_ssn = 1;
    Active_ForceDropPacket();
}

static inline int Active_PacketWouldBeDropped (void)
{
    return (active_drop_pkt == ACTIVE_WOULD_DROP );
}

static inline int Active_PacketForceDropped (void)
{
    return (active_drop_pkt == ACTIVE_FORCE_DROP );
}

static inline int Active_PacketWasDropped (void)
{
    return ( active_drop_pkt == ACTIVE_DROP ) || Active_PacketForceDropped();
}

static inline int Active_SessionWasDropped (void)
{
    return ( active_drop_ssn != 0 );
}

static inline int Active_ResponseQueued (void)
{
    return ( active_have_rsp != 0 );
}

static inline void Active_SetTunnelBypass (void)
{
    active_tunnel_bypass++;
}

static inline void Active_ClearTunnelBypass (void)
{
    active_tunnel_bypass--;
}

static inline int Active_GetTunnelBypass (void)
{
    return ( active_tunnel_bypass > 0 );
}

// drops current session with active response invoked
// for rules with action = drop | sdrop | reject
int Active_DropAction(Packet*);

// drops current session w/o active response invoked
// for rules with custom response = resp3 | react
int Active_IgnoreSession(Packet*);

// force drops the current session w/o active response invoked
// ignores policy/inline test mode and treat drop as alert
int Active_ForceDropAction(Packet *p);

// force drops the current session with active response invoked
// ignores policy/inline test mode and treat drop as alert
int Active_ForceDropResetAction(Packet *p);

#endif // ACTIVE_H

