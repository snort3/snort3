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

#ifndef PATTERN_MATCH_DATA_H
#define PATTERN_MATCH_DATA_H

#include <ctype.h>
#include <sys/time.h>

#include "main/snort_types.h"
#include "detection/treenodes.h"

struct PmdLastCheck
{
    struct timeval ts;
    uint64_t packet_number;
    uint32_t rebuild_flag;
};

struct PatternMatchData
{
    // used by both
    bool negated;        // search for "not this pattern"
    bool fp;             // For fast_pattern arguments
    bool no_case;        // Toggle case sensitivity
    bool relative;       // do relative pattern searching

    uint16_t fp_offset;
    uint16_t fp_length;

    int offset;              // pattern search start offset
    int depth;               // pattern search depth

    unsigned pattern_size;   // size of app layer pattern
    const char* pattern_buf; // app layer pattern to match on

    bool literal;            // set to plain contents

    // not used by ips_content
    int8_t fp_only;
    uint8_t pm_type;

    unsigned replace_size;   // size of app layer replace pattern
    const char* replace_buf; // app layer pattern to replace with

    // FIXIT-L wasting some memory here:
    // - this is not used by content option logic directly
    // - and only used on current eval (not across packets)
    // (partly mitigated by only allocating if excpetion_flag is set)
    //
    /* Set if fast pattern matcher found a content in the packet,
       but the rule option specifies a negated content. Only
       applies to negative contents that are not relative */
    PmdLastCheck* last_check;

    bool unbounded() const
    { return !depth; }

    bool can_be_fp() const;
};

inline bool PatternMatchData::can_be_fp() const
{
    if ( !pattern_buf || !pattern_size )
        return false;

    if ( !negated )
        return true;

    // Negative contents can only be considered if they are not
    // relative and don't have any offset or depth.  This is because
    // the pattern matcher does not take these into consideration and
    // may find the content in a non-relevant section of the payload
    // and thus disable the rule when it shouldn't be.

    // Also case sensitive patterns cannot be considered since patterns
    // are inserted into the pattern matcher without case which may
    // lead to false negatives.

    if ( relative || !no_case || offset || depth )
        return false;

    return true;
}

#endif

