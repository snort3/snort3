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
**    This file gets the correct CPU usage for SMP linux machines.
**
*/
#include "proc_pid_stats.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX_SMP

#include <stdlib.h>
#include <stdio.h>
#include <linux/param.h>
#include <sys/types.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "utils/util.h"
#include "main/thread.h"

#define PROC_STAT       "/proc/stat"
#define PROC_SELF_CPU   "/proc/self/cpu"
#define PROC_SELF_STAT  "/proc/self/stat"

typedef struct _USERSYS
{
    u_long user;
    u_long sys;
    u_long idle;
} USERSYS;

static THREAD_LOCAL int gnum_cpus = 1;

static THREAD_LOCAL USERSYS* gpStatCPUs = nullptr;
static THREAD_LOCAL USERSYS* gpStatCPUs_2 = nullptr;

static THREAD_LOCAL FILE* proc_stat;

static int get_proc_stat_cpu(USERSYS* cpu_stats, int num_cpus)
{
    int iRet;
    int iCtr;
    u_long ulUser;
    u_long ulNice;
    u_long ulSys;
    u_long ulIdle;
    char buf[256];

    rewind(proc_stat);

    /*
    **  Read the total CPU usage, don't use right now.
    **
    **  But we do want to read it if there is only one CPU.
    */
    if (num_cpus != 1)
    {
        if (!fgets(buf, sizeof(buf), proc_stat))
            return -1;
    }

    /*
    **  Read the individual CPU usages.  This tells us where
    **  sniffing and snorting is occurring.
    */
    for (iCtr = 0; iCtr < num_cpus; iCtr++)
    {
        if (!fgets(buf, sizeof(buf), proc_stat))
            return -1;

        iRet = sscanf(buf, "%*s %lu %lu %lu %lu",
            &ulUser, &ulNice, &ulSys, &ulIdle);

        if (iRet == EOF || iRet < 4)
            return -1;

        cpu_stats[iCtr].user = ulUser + ulNice;
        cpu_stats[iCtr].sys  = ulSys;
        cpu_stats[iCtr].idle = ulIdle;
    }

    return 0;
}

static int GetCpuNum(void)
{
    int iRet;
    int num_cpus = 0;
    char acCpuName[10+1];
    char buf[256];

    rewind(proc_stat);

    while (1)
    {
        if (!fgets(buf, sizeof(buf), proc_stat))
            return 0;

        iRet = sscanf(buf, "%10s %*u %*u %*u %*u", acCpuName);

        if (errno == ERANGE)
            errno = 0;

        if (iRet < 1 || iRet == EOF )
        {
            return 0;
        }

        acCpuName[sizeof(acCpuName)-1] = 0x00;

        if (strncmp(acCpuName, "cpu", 3))
        {
            break;
        }

        num_cpus++;
    }

    /*
    **  If there are more then one CPU, then we subtract one because
    **  the first CPU entry combines all CPUs.  This should be
    **  backward compatible with 2.2 not compiled with SMP support.
    */
    if (num_cpus > 1)
        num_cpus--;

    return num_cpus;
}

int init_proc_pid_stats(ProcPIDStats* proc_pid_stats)
{
    /* Do not re-allocate memory */
    if (gpStatCPUs)
        return 0;

    proc_stat = fopen(PROC_STAT, "r");
    if (!proc_stat)
    {
        FatalError("PERFMONITOR: Can't open %s.", PROC_STAT);
    }

    gnum_cpus = GetCpuNum();
    if (gnum_cpus <= 0)
    {
        FatalError("PERFMONITOR: Error reading CPUs from %s.",
            PROC_STAT);
    }

    gpStatCPUs   = (USERSYS*)calloc(gnum_cpus, sizeof(USERSYS));
    if (!gpStatCPUs)
        FatalError("PERFMONITOR: Error allocating CPU mem.");

    gpStatCPUs_2 = (USERSYS*)calloc(gnum_cpus, sizeof(USERSYS));
    if (!gpStatCPUs_2)
        FatalError("PERFMONITOR: Error allocating CPU mem.");

    /*
    **  Allocate for proc_pid_stats CPUs
    */
    proc_pid_stats->sys_cpus = (CPUStats*)calloc(gnum_cpus, sizeof(CPUStats));
    if (!proc_pid_stats->sys_cpus)
        FatalError("PERFMONITOR: Error allocating SysCPU mem.");

    proc_pid_stats->num_cpus = gnum_cpus;

    if (get_proc_stat_cpu(gpStatCPUs, gnum_cpus))
        FatalError("PERFMONITOR: Error while reading '%s'.",
            PROC_STAT);

    fclose(proc_stat);

    return 0;
}

void free_proc_pid_stats(ProcPIDStats* proc_pid_stats)
{
    if (gpStatCPUs)
    {
        free(gpStatCPUs);
        gpStatCPUs = nullptr;
    }

    if (gpStatCPUs_2)
    {
        free(gpStatCPUs_2);
        gpStatCPUs_2 = nullptr;
    }

    if (proc_pid_stats->sys_cpus)
    {
        free(proc_pid_stats->sys_cpus);
        proc_pid_stats->sys_cpus = nullptr;
    }
}

int process_proc_pid_stats(ProcPIDStats* proc_pid_stats)
{
    static THREAD_LOCAL int iError = 0;
    int iCtr;
    u_long ulCPUjiffies;

    proc_stat = fopen(PROC_STAT, "r");
    if (!proc_stat)
    {
        if (!iError)
        {
            ErrorMessage("PERFMONITOR ERROR: Cannot open %s.", PROC_STAT);
            iError = 1;
        }

        return -1;
    }

    if (get_proc_stat_cpu(gpStatCPUs_2, gnum_cpus))
    {
        if (!iError)
        {
            ErrorMessage("PERFMONITOR ERROR: Error while reading '%s'.",
                PROC_STAT);
            iError = 1;
        }

        return -1;
    }

    fclose(proc_stat);

    /*
    **  sys_cpus (The system's CPU usage, like top gives you)
    */
    for (iCtr = 0; iCtr < gnum_cpus; iCtr++)
    {
        ulCPUjiffies = (gpStatCPUs_2[iCtr].user - gpStatCPUs[iCtr].user) +
            (gpStatCPUs_2[iCtr].sys - gpStatCPUs[iCtr].sys) +
            (gpStatCPUs_2[iCtr].idle - gpStatCPUs[iCtr].idle);

        if (gpStatCPUs_2[iCtr].user > gpStatCPUs[iCtr].user)
        {
            proc_pid_stats->sys_cpus[iCtr].user = (((double)(gpStatCPUs_2[iCtr].user -
                gpStatCPUs[iCtr].user)) /
                ulCPUjiffies) * 100.0;
            if (proc_pid_stats->sys_cpus[iCtr].user < .01)
            {
                proc_pid_stats->sys_cpus[iCtr].user = 0;
            }
        }
        else
        {
            proc_pid_stats->sys_cpus[iCtr].user = 0;
        }

        if (gpStatCPUs_2[iCtr].sys > gpStatCPUs[iCtr].sys)
        {
            proc_pid_stats->sys_cpus[iCtr].sys = (((double)(gpStatCPUs_2[iCtr].sys -
                gpStatCPUs[iCtr].sys)) /
                ulCPUjiffies) * 100.0;
            if (proc_pid_stats->sys_cpus[iCtr].sys < .01)
            {
                proc_pid_stats->sys_cpus[iCtr].sys = 0;
            }
        }
        else
        {
            proc_pid_stats->sys_cpus[iCtr].sys = 0;
        }

        if (gpStatCPUs_2[iCtr].idle > gpStatCPUs[iCtr].idle)
        {
            proc_pid_stats->sys_cpus[iCtr].idle = (((double)(gpStatCPUs_2[iCtr].idle -
                gpStatCPUs[iCtr].idle)) /
                ulCPUjiffies) * 100.0;
            if (proc_pid_stats->sys_cpus[iCtr].idle < .01)
            {
                proc_pid_stats->sys_cpus[iCtr].idle = 0;
            }
        }
        else
        {
            proc_pid_stats->sys_cpus[iCtr].idle = 0;
        }

        /*
        **  Set statistics for next processing.
        */
        gpStatCPUs[iCtr].user  = gpStatCPUs_2[iCtr].user;
        gpStatCPUs[iCtr].sys   = gpStatCPUs_2[iCtr].sys;
        gpStatCPUs[iCtr].idle  = gpStatCPUs_2[iCtr].idle;
    }

    return 0;
}

#endif

