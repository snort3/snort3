//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef DETECT_H
#define DETECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "parser/parser.h"
#include "log/log.h"
#include "events/event.h"

struct ProfileStats;

extern SO_PUBLIC THREAD_LOCAL bool do_detect;
extern SO_PUBLIC THREAD_LOCAL bool do_detect_content;

extern THREAD_LOCAL ProfileStats eventqPerfStats;
extern THREAD_LOCAL ProfileStats detectPerfStats;
extern THREAD_LOCAL ProfileStats rebuiltPacketPerfStats;

// main loop hooks
void snort_ignore(Packet*);
void snort_inspect(Packet*);
void snort_log(Packet*);

// detection only (no decode or inspection)
SO_PUBLIC bool snort_detect(Packet*);

// parsing
int RuleListEnd(Packet*, RuleTreeNode*, RuleFpList*, int);
int OptListEnd(void* option_data, class Cursor&, Packet*);

// detection
int CheckBidirectional(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcIP(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstIP(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcPortEqual(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortEqual(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcPortNotEq(Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortNotEq(Packet*, RuleTreeNode*, RuleFpList*, int);

// alerts
void CallLogFuncs(Packet*, ListHead*, Event*, const char*);
void CallLogFuncs(Packet*, const OptTreeNode*, ListHead*);
void CallAlertFuncs(Packet*, const OptTreeNode*, ListHead*);

// don't eval content rules
// non-content rules are still evaluated
inline void DisableDetect()
{
    do_detect_content = false;
}

// don't want to do any detection with rules
// (no content and no non-content)
inline void DisableInspection()
{
    do_detect = do_detect_content = false;
}

#endif

