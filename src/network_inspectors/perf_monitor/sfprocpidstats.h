//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
/*
** Dan Roelker <droelker@sourcefire.com>
**
**  DESCRIPTION
**    This file gets the correct CPU usage for SMP Linux machines.
*/
#ifndef SFPROCPIDSTATS_H
#define SFPROCPIDSTATS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX_SMP

typedef struct _CPUSTAT
{
    double user;
    double sys;
    double total;
    double idle;
} CPUSTAT;

typedef struct _SFPROCPIDSTATS
{
    CPUSTAT* SysCPUs;

    int iCPUs;
} SFPROCPIDSTATS;

/* Init CPU usage processing */
int sfInitProcPidStats(SFPROCPIDSTATS* sfProcPidStats);

/* Fetch the CPU utilization numbers for process */
int sfProcessProcPidStats(SFPROCPIDSTATS* sfProcPidStats);

/* Free the statistics structure */
void FreeProcPidStats(SFPROCPIDSTATS* sfProcPidStats);

#endif

#endif

