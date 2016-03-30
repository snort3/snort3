//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
** Carter Waxman <cwaxman@cisco.com>
** Based on work by Dan Roelker <droelker@sourcefire.com>
**
**  DESCRIPTION
**    This file gets the correct CPU usage for SMP Linux machines.
*/
#ifndef PROC_PID_STATS_H
#define PROC_PID_STATS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX_SMP

struct CPUStats
{
    double user;
    double sys;
    double total;
    double idle;
};

struct ProcPIDStats
{
    CPUStats* sys_cpus;

    int num_cpus;
};

/* Init CPU usage processing */
int init_proc_pid_stats(ProcPIDStats*);

/* Fetch the CPU utilization numbers for process */
int process_proc_pid_stats(ProcPIDStats*);

/* Free the statistics structure */
void free_proc_pid_stats(ProcPIDStats*);

#endif

#endif

