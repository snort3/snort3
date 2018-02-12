//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// sf_mlmp.h author Sourcefire Inc.

#ifndef SF_MULTI_PART_MPSE_H
#define SF_MULTI_PART_MPSE_H

#include <cstddef>
#include <cstdint>

struct tMlmpPattern
{
    /*binary pattern */
    const uint8_t* pattern;

    /*binary pattern length in bytes */
    size_t patternSize;

    /**level of pattern. It should start from 0.*/
    uint32_t level;
};

struct tMlmpTree;

tMlmpTree* mlmpCreate();
int mlmpAddPattern(tMlmpTree*, const tMlmpPattern*, void* metaData);
int mlmpProcessPatterns(tMlmpTree*);
void* mlmpMatchPatternUrl(tMlmpTree*, tMlmpPattern*);
void* mlmpMatchPatternGeneric(tMlmpTree*, tMlmpPattern*);
void mlmpDestroy(tMlmpTree*);
void mlmpDump(tMlmpTree*);

#endif

