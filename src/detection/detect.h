/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*  I N C L U D E S  ************************************************/
#ifndef DETECT_H
#define DETECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_debug.h"
#include "protocols/packet.h"
#include "rules.h"
#include "treenodes.h"
#include "parser.h"
#include "profiler.h"
#include "log.h"
#include "event.h"
#include "utils/sfportobject.h"

/*  P R O T O T Y P E S  ******************************************************/
extern THREAD_LOCAL int do_detect;
extern THREAD_LOCAL int do_detect_content;

#ifdef PERF_PROFILING
extern THREAD_LOCAL ProfileStats eventqPerfStats;
extern THREAD_LOCAL ProfileStats detectPerfStats;
#endif

/* detection/manipulation funcs */
void snort_ignore(Packet*);
void snort_inspect(Packet*);
int Detect(Packet *);
void CallOutputPlugins(Packet *);
int EvalPacket(ListHead *, int, Packet * );
int EvalHeader(RuleTreeNode *, Packet *, int);
int EvalOpts(OptTreeNode *, Packet *);
void TriggerResponses(Packet *, OptTreeNode *);

int CheckAddrPort(sfip_var_t *, PortObject* , Packet *, uint32_t, int);

/* detection modules */
int CheckBidirectional(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckSrcIP(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckDstIP(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckSrcIPNotEq(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckDstIPNotEq(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckSrcPortEqual(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckDstPortEqual(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckSrcPortNotEq(Packet *, RuleTreeNode *, RuleFpList *, int);
int CheckDstPortNotEq(Packet *, RuleTreeNode *, RuleFpList *, int);

int RuleListEnd(Packet *, RuleTreeNode *, RuleFpList *, int);
int OptListEnd(void* option_data, class Cursor&, Packet*);

void snort_log(Packet*);
void CallLogFuncs(Packet*, Event*, const char*);
void CallLogFuncs(Packet*, const OptTreeNode*, ListHead*);
void CallAlertFuncs(Packet*, const OptTreeNode*, ListHead*);

// don't eval content rules
// non-content rules are still evaluated
static inline void DisableDetect(Packet*)
{
    do_detect_content = 0;
}

// don't want to do any detection with rules
// (no content and no non-content)
static inline void DisableInspection(Packet*)
{
    do_detect = do_detect_content = 0;
}

/* counter for number of times we evaluate rules.  Used to
 * cache result of check for rule option tree nodes. */
extern THREAD_LOCAL uint64_t rule_eval_pkt_count;


#endif /* DETECT_H */
