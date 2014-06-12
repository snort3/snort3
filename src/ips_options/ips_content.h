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

#ifndef IPS_CONTENT_H
#define IPS_CONTENT_H

#include <ctype.h>

#include "snort.h"
#include "snort_debug.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/detection_util.h"

extern THREAD_LOCAL int lastType;

#define CHECK_AND_PATTERN_MATCH 1
#define CHECK_URI_PATTERN_MATCH 2

struct PmdLastCheck
{
    struct timeval ts;
    uint64_t packet_number;
    uint32_t rebuild_flag;
 };

typedef struct _PatternMatchData
{
    // FIXIT below must be thread local or the cloned instance must be
    // thread local because they are updated :(
    int offset;             /* pattern search start offset */
    int depth;              /* pattern search depth */

    int distance;           /* offset to start from based on last match */
    unsigned within;           /* this pattern must be found
                               within X bytes of last match*/
    // FIXIT above must be thread local or the cloned instance must be
    // thread local because they are updated :(

    int8_t offset_var;      /* byte_extract variable indices for offset, */
    int8_t depth_var;       /* depth, distance, within */
    int8_t distance_var;
    int8_t within_var;

    int rawbytes;           /* Search the raw bytes rather than any decoded app
                               buffer */

    int nocase;             /* Toggle case insensitity */
    int use_doe;            /* Use the doe_ptr for relative pattern searching */
    HTTP_BUFFER http_buffer;/* Index of the URI buffer */
    int buffer_func;        /* buffer function CheckAND or CheckUri */
    unsigned pattern_size;     /* size of app layer pattern */
    unsigned replace_size;     /* size of app layer replace pattern */
    char *replace_buf;      /* app layer pattern to replace with */
    char *pattern_buf;      /* app layer pattern to match on */
    int (*search)(const char *, int, struct _PatternMatchData *);  /* search function */
    int *skip_stride; /* B-M skip array */
    int *shift_stride; /* B-M shift array */
    unsigned pattern_max_jump_size; /* Maximum distance we can jump to search for
                                  * this pattern again. */

    /* For fast_pattern arguments */
    uint8_t fp;
    uint8_t fp_only;
    uint16_t fp_offset;
    uint16_t fp_length;

    uint8_t exception_flag; /* search for "not this pattern" */

    int* replace_depth;      /* >=0 is offset to start of replace */

    // FIXIT wasting some memory here:
    // - this is not used by content option logic directly
    // - and only used on current eval (not across packets)
    // (partly mitigated by only allocating if excpetion_flag is set)
    //
    /* Set if fast pattern matcher found a content in the packet,
       but the rule option specifies a negated content. Only
       applies to negative contents that are not relative */
    PmdLastCheck* last_check;

} PatternMatchData;

void PatternMatchDuplicatePmd(void *, PatternMatchData *);
int eval_dup_content(void* v, struct Packet* p, PatternMatchData* alt);

int PatternMatchAdjustRelativeOffsets(
    void*, PatternMatchData *dup_pmd,
    const uint8_t *current_cursor, const uint8_t *orig_cursor);

// FIXIT if really needed, would b better as specific method
// so PMD isn't exposed
PatternMatchData* get_pmd(OptFpList*);
bool is_fast_pattern_only(OptFpList*);
bool is_unbounded(void*);

static inline bool IsHttpBufFpEligible (HTTP_BUFFER http_buffer)
{
    switch ( http_buffer )
    {
    case HTTP_BUFFER_URI:
    case HTTP_BUFFER_HEADER:
    case HTTP_BUFFER_CLIENT_BODY:
        return true;
    default:
        break;
    }
    return false;
}

#endif

