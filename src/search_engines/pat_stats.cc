//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "pat_stats.h"
#include "log/messages.h"

THREAD_LOCAL PatMatQStat pmqs;

void print_pat_stats(const char* type, unsigned max)
{
    if ( !pmqs.max_inq )
        return;

    LogMessage("%s: queue max      = " STDu64 "\n", type, pmqs.max_inq);
    LogMessage("%s: queue limit    = " STDu64 "\n", type, (PegCount)max);
    LogMessage("%s: queue flushes  = " STDu64 "\n", type, pmqs.tot_inq_flush);
    LogMessage("%s: queue inserts  = " STDu64 "\n", type, pmqs.tot_inq_inserts);
    LogMessage("%s: queue uinserts = " STDu64 "\n", type, pmqs.tot_inq_uinserts);
}

