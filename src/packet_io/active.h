//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// @file    active.h
// @author  Russ Combs <rcombs@sourcefire.com>

#ifndef ACTIVE_H
#define ACTIVE_H

#include "main/snort_types.h"
#include "protocols/packet.h"
#include "protocols/packet_manager.h"
#include "main/snort.h"
#include "utils/stats.h"
#include "packet_io/sfdaq.h"

struct Packet;

int Active_Init(SnortConfig*);
int Active_Term(void);

SO_PUBLIC uint64_t Active_GetInjects(void);

// NULL flags implies ENC_FLAG_FWD
SO_PUBLIC void Active_KillSession(Packet*, EncodeFlags*);

SO_PUBLIC void Active_SendReset(Packet*, EncodeFlags);
SO_PUBLIC void Active_SendUnreach(Packet*, UnreachResponse);
SO_PUBLIC bool Active_SendData(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);
SO_PUBLIC void Active_InjectData(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);

SO_PUBLIC int Active_IsRSTCandidate(const Packet*);
SO_PUBLIC int Active_IsUNRCandidate(const Packet*);

SO_PUBLIC int Active_IsEnabled(void);
SO_PUBLIC void Active_SetEnabled(int on_off);

enum tActiveDrop
{
    ACTIVE_ALLOW = 0,      // don't drop
    ACTIVE_CANT_DROP = 1,  // can't drop
    ACTIVE_WOULD_DROP = 2, // would drop
    ACTIVE_DROP = 3,       // should drop
    ACTIVE_FORCE_DROP = 4, // must drop
};

enum tActiveSsnDrop
{
    ACTIVE_SSN_ALLOW,       // don't drop
    ACTIVE_SSN_DROP,        // can drop and reset
    ACTIVE_SSN_DROP_WITHOUT_RESET,  // can drop but without reset
};


SO_PUBLIC extern THREAD_LOCAL tActiveDrop active_drop_pkt;
SO_PUBLIC extern THREAD_LOCAL tActiveSsnDrop active_drop_ssn;
SO_PUBLIC extern THREAD_LOCAL int active_have_rsp;
SO_PUBLIC extern THREAD_LOCAL int active_tunnel_bypass;
SO_PUBLIC extern THREAD_LOCAL int active_suspend;

static inline void Active_Reset (void)
{
    active_drop_pkt = ACTIVE_ALLOW;
    active_drop_ssn = ACTIVE_SSN_ALLOW;
    active_have_rsp = 0;
    active_tunnel_bypass = 0;
}

static inline void Active_Suspend (void)
{ active_suspend = 1; }

static inline void Active_Resume (void)
{ active_suspend = 0; }

static inline bool Active_Suspended (void)
{ return ( active_suspend != 0 ); }

static inline tActiveDrop Active_GetDisposition (void)
{ return active_drop_pkt; }

static inline void Active_CantDrop(void)
{
#if 0
    // not yet supported
    if ( active_drop_pkt < ACTIVE_CANT_DROP )
        active_drop_pkt = ACTIVE_CANT_DROP;
#else
    if ( active_drop_pkt < ACTIVE_WOULD_DROP )
        active_drop_pkt = ACTIVE_WOULD_DROP;
#endif
}

static inline void Active_ForceDropPacket (void)
{
    if ( Active_Suspended() )
        Active_CantDrop();
    else
        active_drop_pkt = ACTIVE_FORCE_DROP;
 }

static inline void Active_DropPacket(const Packet* p)
{
    if ( Active_Suspended() )
    {
        Active_CantDrop();
    }
    else if ( active_drop_pkt != ACTIVE_FORCE_DROP )
    {
        if ( ScInlineMode() )
        {
            if ( DAQ_GetInterfaceMode(p->pkth) == DAQ_MODE_INLINE )
                active_drop_pkt = ACTIVE_DROP;
            else
                active_drop_pkt = ACTIVE_WOULD_DROP;
        }
        else if ( ScInlineTestMode() )
        {
            active_drop_pkt = ACTIVE_WOULD_DROP;
        }
    }
}

static inline void Active_DAQDropPacket(const Packet *p)
{
    if ( Active_Suspended() )
    {
        Active_CantDrop();
    }
    else if ( active_drop_pkt != ACTIVE_FORCE_DROP )
    {
        if ( DAQ_GetInterfaceMode(p->pkth) == DAQ_MODE_INLINE )
            active_drop_pkt = ACTIVE_DROP;
        else
            active_drop_pkt = ACTIVE_WOULD_DROP;
    }
}

static inline void _Active_DropSession (const Packet* p, tActiveSsnDrop ssn_drop)
{
    if ( Active_Suspended() )
    {
        Active_CantDrop();
    }
    else
    {
        active_drop_ssn = ssn_drop;
        Active_DropPacket(p);
    }
}

static inline void _Active_ForceDropSession (tActiveSsnDrop ssn_drop)
{
    if ( Active_Suspended() )
    {
        Active_CantDrop();
    }
    else
    {
        active_drop_ssn = ssn_drop;
        Active_ForceDropPacket();
    }
}

static inline void Active_DropSession (const Packet* p)
{ _Active_DropSession(p, ACTIVE_SSN_DROP); }

static inline void Active_ForceDropSession (void)
{ _Active_ForceDropSession(ACTIVE_SSN_DROP); }

static inline void Active_DropSessionWithoutReset (const Packet* p)
{ _Active_DropSession(p, ACTIVE_SSN_DROP_WITHOUT_RESET); }

static inline void Active_ForceDropSessionWithoutReset (void)
{ _Active_ForceDropSession(ACTIVE_SSN_DROP_WITHOUT_RESET); }

static inline int Active_PacketWouldBeDropped (void)
{ return (active_drop_pkt == ACTIVE_WOULD_DROP ); }

static inline int Active_PacketForceDropped (void)
{ return (active_drop_pkt == ACTIVE_FORCE_DROP ); }

static inline int Active_PacketWasDropped (void)
{ return ( active_drop_pkt >= ACTIVE_DROP ); }

static inline int Active_SessionWasDropped (void)
{ return ( active_drop_ssn != ACTIVE_SSN_ALLOW ); }

/* SNORT2.9.7 has an
// #ifdef ACTIVE_RESPONSE */
static inline int Active_ResponseQueued (void)
{ return ( active_have_rsp != ACTIVE_SSN_ALLOW ); }
//#endif /* ACTIVE_RESPONSE */

static inline void Active_SetTunnelBypass (void)
{ active_tunnel_bypass++; }

static inline void Active_ClearTunnelBypass (void)
{ active_tunnel_bypass--; }

static inline int Active_GetTunnelBypass (void)
{ return ( active_tunnel_bypass > 0 ); }

// drops current session with active response invoked
// for rules with action = drop | sdrop | reject
SO_PUBLIC int Active_DropAction(Packet*);

// drops current session w/o active response invoked
// for rules with custom response = resp3 | react
SO_PUBLIC int Active_IgnoreSession(Packet*);

// force drops the current session w/o active response invoked
// ignores policy/inline test mode and treat drop as alert
SO_PUBLIC int Active_ForceDropAction(Packet *p);

// force drops the current session with active response invoked
// ignores policy/inline test mode and treat drop as alert
SO_PUBLIC int Active_ForceDropResetAction(Packet *p);

SO_PUBLIC const char* Active_GetDispositionString();

#endif // ACTIVE_H
