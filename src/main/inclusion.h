//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

#ifndef SNORT_INCLUSION_H
#define SNORT_INCLUSION_H

SNORT_FORCED_INCLUSION_EXTERN(base64_encoder);
SNORT_FORCED_INCLUSION_EXTERN(jsnorm);
SNORT_FORCED_INCLUSION_EXTERN(kmap);
SNORT_FORCED_INCLUSION_EXTERN(utf);
SNORT_FORCED_INCLUSION_EXTERN(u2_pseudo_header);

bool extern_symbols[] =
{
    SNORT_FORCED_INCLUSION_SYMBOL(base64_encoder),
    SNORT_FORCED_INCLUSION_SYMBOL(jsnorm),
    SNORT_FORCED_INCLUSION_SYMBOL(kmap),
    SNORT_FORCED_INCLUSION_SYMBOL(utf),
    SNORT_FORCED_INCLUSION_SYMBOL(u2_pseudo_header)
};

#endif
