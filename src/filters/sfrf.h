//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// sfrf.h author Dilbagh Chahal <dchahal@sourcefire.com>

#ifndef SFRF_H
#define SFRF_H

#include <ctime>
#include <mutex>

#include "framework/counts.h"
#include "framework/ips_action.h"
#include "main/policy.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_ipvar.h"

namespace snort
{
class GHash;
struct SfIp;
struct SnortConfig;
}

#define SFRF_MAX_GENID 8129

typedef enum
{
    SFRF_TRACK_BY_SRC = 1,
    SFRF_TRACK_BY_DST,
    SFRF_TRACK_BY_RULE,
    SFRF_TRACK_BY_MAX
} SFRF_TRACK;


typedef enum
{
    SFRF_COUNT_NOP,
    SFRF_COUNT_RESET,
    SFRF_COUNT_INCREMENT,
    SFRF_COUNT_DECREMENT,
    SFRF_COUNT_MAX
} SFRF_COUNT_OPERATION;

typedef enum
{
    FS_NEW = 0, FS_OFF, FS_ON, FS_MAX
} FilterState;

struct tSFRFConfigNode
{
    int tid;
    unsigned gid;
    unsigned sid;
    PolicyId policyId;
    SFRF_TRACK tracking;
    unsigned count;
    unsigned seconds;

    // Action that replaces original rule action on reaching threshold
    snort::IpsAction::Type newAction;

    // Threshold action duration in seconds before reverting to original rule action
    unsigned timeout;
    sfip_var_t* applyTo;
};

struct tSFRFSidNode
{
    PolicyId policyId;
    unsigned gid;
    unsigned sid;
    struct sf_list* configNodeList;
};

struct tSFRFGenHashKey
{
    PolicyId policyId;
    unsigned sid;
};

struct RateFilterConfig
{
    /* Array of hash, indexed by gid. Each array element is a hash, which
     * is keyed on sid/policyId and data is a tSFRFSidNode node.
     */
    snort::GHash* genHash [SFRF_MAX_GENID];

    unsigned memcap;
    unsigned noRevertCount;
    int count;
    int internal_event_mask;
};

struct RateFilterStats
{
    PegCount xhash_nomem_peg = 0;
};

void SFRF_Delete();
void SFRF_Flush();
int SFRF_ConfigAdd(snort::SnortConfig*, RateFilterConfig*, tSFRFConfigNode*);

int SFRF_TestThreshold(RateFilterConfig *config, unsigned gid, unsigned sid,
    PolicyId policyid, const snort::SfIp *sip, const snort::SfIp *dip,
    time_t curTime, SFRF_COUNT_OPERATION);

void SFRF_ShowObjects(RateFilterConfig*);

int SFRF_Alloc(unsigned int memcap);

inline void enable_internal_event(RateFilterConfig* config, uint32_t sid)
{
    if (config == nullptr)
        return;

    config->internal_event_mask |= (1 << sid);
}

inline bool is_internal_event_enabled(RateFilterConfig* config, uint32_t sid)
{
    if (config == nullptr)
        return false;

    return (config->internal_event_mask & (1 << sid));
}

static std::mutex sfrf_hash_mutex;

#endif
