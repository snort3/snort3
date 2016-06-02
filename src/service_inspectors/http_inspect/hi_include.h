//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef HI_INCLUDE_H
#define HI_INCLUDE_H

#include "framework/counts.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/thread.h"

#define HI_UNKNOWN_METHOD 1
#define HI_POST_METHOD 2
#define HI_GET_METHOD 4

struct HIStats
{
    PegCount total;
    PegCount get;              /* Number of GETs */
    PegCount post;             /* Number of POST methods encountered */

    PegCount req_headers;      /* Number of successfully extracted request headers */
    PegCount resp_headers;     /* Number of successfully extracted response headers */
    PegCount req_cookies;      /* Number of successfully extracted request cookies */
    PegCount resp_cookies;     /* Number of successfully extracted response cookies */
    PegCount post_params;      /* Number of successfully extract post parameters */

    PegCount unicode;
    PegCount double_unicode;
    PegCount non_ascii;        /* Non ASCII-representable character in URL */
    PegCount dir_trav;         /* '../' */
    PegCount slashes;          /* '//' */
    PegCount self_ref;         /* './' */

    PegCount gzip_pkts;
    PegCount compr_bytes_read;
    PegCount decompr_bytes_read;
};

extern THREAD_LOCAL HIStats hi_stats;
extern const PegInfo peg_names[];

#endif

