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

// sf_multi_mpse.h author Sourcefire Inc.

#ifndef SF_MULTI_MPSE_H
#define SF_MULTI_MPSE_H

#include <cstddef>
#include <cstdint>

struct tMlpPattern
{
    const uint8_t* pattern;
    size_t patternSize;
};

void* mlpCreate();
int mlpAddPattern(void* root, const tMlpPattern**, void* metaData);
int mlpProcessPatterns(void* root);
void* mlpMatchPatternLongest(void* root, tMlpPattern**);
void* mlpMatchPatternUrl(void* root, tMlpPattern**);
void* mlpMatchPatternCustom(void* root, tMlpPattern**,
    int (* callback)(void*, void*, int, void*, void*));
void mlpDestroy(void* root);
void mlpDump(void* root);
void* mlpGetPatternMatcherTree(void* root, tMlpPattern**);

#endif

