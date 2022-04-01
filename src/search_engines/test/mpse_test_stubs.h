////--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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

// mpse_test_stubs.h author Russ Combs <rucombs@cisco.com>

#ifndef TEST_STUBS_H
#define TEST_STUBS_H

#include <cassert>

#include "detection/fp_config.h"
#include "framework/base_api.h"
#include "framework/mpse.h"
#include "framework/mpse_batch.h"
#include "main/snort_config.h"
#include "managers/mpse_manager.h"
#include "utils/stats.h"

#include "search_engines/pat_stats.h"

extern std::vector<void *> s_state;
extern snort::ScratchAllocator* scratcher;

namespace snort
{
extern SnortConfig s_conf;

extern THREAD_LOCAL SnortConfig* snort_conf;
extern THREAD_LOCAL PatMatQStat pmqs;

extern unsigned parse_errors;
} // namespace snort

extern snort::Mpse* mpse;
const snort::MpseApi* get_test_api();

extern void* s_user;
extern void* s_tree;
extern void* s_list;

extern MpseAgent s_agent;

extern const snort::BaseApi* se_ac_bnfa;
extern const snort::BaseApi* se_ac_full;
extern const snort::BaseApi* se_hyperscan;

struct ExpectedMatch
{
    int id;
    int offset;
};

extern const ExpectedMatch* s_expect;
extern int s_found;

int check_mpse_match(
    void* pid, void* /*tree*/, int index, void* /*context*/, void* /*neg_list*/);

#endif

