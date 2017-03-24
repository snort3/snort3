//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// fp_detect.h is derived from fpdetect.h by:
//
// Dan Roelker <droelker@sourcefire.com>
// Marc Norton <mnorton@sourcefire.com>

#ifndef FPDETECT_H
#define FPDETECT_H

// this is where the high-level fast pattern matching action is
// rule groups are selected based on traffic and any fast pattern
// matches trigger rule tree evaluation.

#include "main/thread.h"

#define REBUILD_FLAGS (PKT_REBUILT_FRAG | PKT_REBUILT_STREAM)

struct Packet;
struct PortGroup;
struct ProfileStats;
struct OptTreeNode;

extern THREAD_LOCAL ProfileStats rulePerfStats;
extern THREAD_LOCAL ProfileStats ruleRTNEvalPerfStats;
extern THREAD_LOCAL ProfileStats ruleOTNEvalPerfStats;
extern THREAD_LOCAL ProfileStats ruleNFPEvalPerfStats;

/*
**  This is the only function that is needed to do an
**  inspection on a packet.
*/
int fpEvalPacket(Packet*);

struct RuleTreeNode;
int fpLogEvent(const RuleTreeNode*, const OptTreeNode*, Packet*);
int fpEvalRTN(RuleTreeNode*, Packet*, int check_ports);

/*
**  This define is for the number of unique events
**  to match before choosing which event to log.
**  (Since we can only log one.) This define is the limit.
*/
#define MAX_EVENT_MATCH 100

/*
**  MATCH_INFO
**  The events that are matched get held in this structure,
**  and iMatchIndex gets set to the event that holds the
**  highest priority.
*/
struct MATCH_INFO
{
    const OptTreeNode* MatchArray[MAX_EVENT_MATCH];
    int iMatchCount;
    int iMatchIndex;
    int iMatchMaxLen;
};

/*
**  OTNX_MATCH_DATA
**  This structure holds information that is
**  referenced during setwise pattern matches.
**  It also contains information regarding the
**  number of matches that have occurred and
**  the event to log based on the event comparison
**  function.
*/
struct OTNX_MATCH_DATA
{
    PortGroup* pg;
    Packet* p;

    const uint8_t* data;
    unsigned size;

    int check_ports;
    bool have_match;

    MATCH_INFO* matchInfo;
    int iMatchInfoArraySize;
};

void otnx_match_data_init(int);
void otnx_match_data_term();

int fpAddMatch(OTNX_MATCH_DATA*, int pLen, const OptTreeNode*);
OptTreeNode* GetOTN(uint32_t gid, uint32_t sid);

/* counter for number of times we evaluate rules.  Used to
 * cache result of check for rule option tree nodes. */
extern THREAD_LOCAL uint64_t rule_eval_pkt_count;

#endif

