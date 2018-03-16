//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef FP_UTILS_H
#define FP_UTILS_H

// fast pattern utilities
#include <vector>
#include "framework/ips_option.h"

struct OptFpList;
struct OptTreeNode;

struct PatternMatchData* get_pmd(OptFpList*, SnortProtocolId, snort::RuleDirection);
bool is_fast_pattern_only(OptFpList*);
void validate_fast_pattern(OptTreeNode*);

int flp_trim(const char* p, int plen, const char** buff);
bool set_fp_content(OptTreeNode*);

std::vector <PatternMatchData*> get_fp_content(
    OptTreeNode*, OptFpList*&, bool srvc, bool only_literals, bool& exclude);

#endif

