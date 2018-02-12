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

#ifndef PATTERN_MATCH_DATA_H
#define PATTERN_MATCH_DATA_H

#include <sys/time.h>
#include <vector>

#include "framework/ips_option.h"  // FIXIT-L not a good dependency

struct PmdLastCheck
{
    struct timeval ts;
    uint64_t context_num;
    uint32_t rebuild_flag;
    uint16_t run_num;
};

struct PatternMatchData
{
    const char* pattern_buf; // app layer pattern to match on

    // FIXIT-L wasting some memory here:
    // - this is not used by content option logic directly
    // - and only used on current eval (not across packets)
    // (partly mitigated by only allocating if exception_flag is set)
    //
    /* Set if fast pattern matcher found a content in the packet,
       but the rule option specifies a negated content. Only
       applies to negative contents that are not relative */
    PmdLastCheck* last_check;

    unsigned pattern_size;   // size of app layer pattern

    int offset;              // pattern search start offset
    int depth;               // pattern search depth

    enum
    {
        NEGATED  = 0x01,
        NO_CASE  = 0x02,
        RELATIVE = 0x04,
        LITERAL  = 0x08,
        FAST_PAT = 0x10,
        NO_FP    = 0x20,
    };

    uint16_t flags;          // from above enum
    uint16_t mpse_flags;     // passed through to mpse

    uint16_t fp_offset;
    uint16_t fp_length;

    // not used by ips_content
    int8_t fp_only;
    uint8_t pm_type;

    bool is_unbounded() const
    { return !depth; }

    void set_fast_pattern()
    { flags |= FAST_PAT; }

    void set_negated()
    { flags |= NEGATED; }

    void set_no_case()
    { flags |= NO_CASE; }

    void set_relative()
    { flags |= RELATIVE; }

    void set_literal()
    { flags |= LITERAL; }

    bool is_fast_pattern() const
    { return (flags & FAST_PAT) != 0; }

    bool is_negated() const
    { return (flags & NEGATED) != 0; }

    bool is_no_case() const
    { return (flags & NO_CASE) != 0; }

    bool is_relative() const
    { return (flags & RELATIVE) != 0; }

    bool is_literal() const
    { return (flags & LITERAL) != 0; }

    bool can_be_fp() const;
};

typedef std::vector<PatternMatchData*> PatternMatchVector;

inline bool PatternMatchData::can_be_fp() const
{
    if ( !pattern_buf or !pattern_size )
        return false;

    if ( flags & NO_FP )
        return false;

    if ( !is_negated() )
        return true;

    // Negative contents can only be considered if they are not
    // relative and don't have any offset or depth.  This is because
    // the pattern matcher does not take these into consideration and
    // may find the content in a non-relevant section of the payload
    // and thus disable the rule when it shouldn't be.

    // Also case sensitive patterns cannot be considered since patterns
    // are inserted into the pattern matcher without case which may
    // lead to false negatives.

    if ( is_relative() or !is_no_case() or offset or depth )
        return false;

    return true;
}

#endif

