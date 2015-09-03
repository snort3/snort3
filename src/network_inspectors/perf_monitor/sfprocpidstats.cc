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
**    This file gets the correct CPU usage for SMP linux machines.
**
*/
#include "sfprocpidstats.h"

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

static THREAD_LOCAL int giCPUs = 1;

static THREAD_LOCAL USERSYS* gpStatCPUs = NULL;
static THREAD_LOCAL USERSYS* gpStatCPUs_2 = NULL;

static THREAD_LOCAL FILE* proc_stat;

static int GetProcStatCpu(USERSYS* pStatCPUs, int iCPUs)
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
    if (iCPUs != 1)
    {
        if (!fgets(buf, sizeof(buf), proc_stat))
            return -1;
    }

    /*
    **  Read the individual CPU usages.  This tells us where
    **  sniffing and snorting is occurring.
    */
    for (iCtr = 0; iCtr < iCPUs; iCtr++)
    {
        if (!fgets(buf, sizeof(buf), proc_stat))
            return -1;

        iRet = sscanf(buf, "%*s %lu %lu %lu %lu",
            &ulUser, &ulNice, &ulSys, &ulIdle);

        if (iRet == EOF || iRet < 4)
            return -1;

        pStatCPUs[iCtr].user = ulUser + ulNice;
        pStatCPUs[iCtr].sys  = ulSys;
        pStatCPUs[iCtr].idle = ulIdle;
    }

    return 0;
}

static int GetCpuNum(void)
{
    int iRet;
    int iCPUs = 0;
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

        iCPUs++;
    }

    /*
    **  If there are more then one CPU, then we subtract one because
    **  the first CPU entry combines all CPUs.  This should be
    **  backward compatible with 2.2 not compiled with SMP support.
    */
    if (iCPUs > 1)
        iCPUs--;

    return iCPUs;
}

int sfInitProcPidStats(SFPROCPIDSTATS* sfProcPidStats)
{
    /* Do not re-allocate memory */
    if (gpStatCPUs != NULL)
        return 0;

    proc_stat = fopen(PROC_STAT, "r");
    if (!proc_stat)
    {
        FatalError("PERFMONITOR: Can't open %s.", PROC_STAT);
    }

    giCPUs = GetCpuNum();
    if (giCPUs <= 0)
    {
        FatalError("PERFMONITOR: Error reading CPUs from %s.",
            PROC_STAT);
    }

    gpStatCPUs   = (USERSYS*)calloc(giCPUs, sizeof(USERSYS));
    if (!gpStatCPUs)
        FatalError("PERFMONITOR: Error allocating CPU mem.");

    gpStatCPUs_2 = (USERSYS*)calloc(giCPUs, sizeof(USERSYS));
    if (!gpStatCPUs_2)
        FatalError("PERFMONITOR: Error allocating CPU mem.");

    /*
    **  Allocate for sfProcPidStats CPUs
    */
    sfProcPidStats->SysCPUs = (CPUSTAT*)calloc(giCPUs, sizeof(CPUSTAT));
    if (!sfProcPidStats->SysCPUs)
        FatalError("PERFMONITOR: Error allocating SysCPU mem.");

    sfProcPidStats->iCPUs = giCPUs;

    if (GetProcStatCpu(gpStatCPUs, giCPUs))
        FatalError("PERFMONITOR: Error while reading '%s'.",
            PROC_STAT);

    fclose(proc_stat);

    return 0;
}

void FreeProcPidStats(SFPROCPIDSTATS* sfProcPidStats)
{
    if (gpStatCPUs != NULL)
    {
        free(gpStatCPUs);
        gpStatCPUs = NULL;
    }

    if (gpStatCPUs_2 != NULL)
    {
        free(gpStatCPUs_2);
        gpStatCPUs_2 = NULL;
    }

    if (sfProcPidStats->SysCPUs != NULL)
    {
        free(sfProcPidStats->SysCPUs);
        sfProcPidStats->SysCPUs = NULL;
    }
}

int sfProcessProcPidStats(SFPROCPIDSTATS* sfProcPidStats)
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

    if (GetProcStatCpu(gpStatCPUs_2, giCPUs))
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
    **  SysCPUs (The system's CPU usage, like top gives you)
    */
    for (iCtr = 0; iCtr < giCPUs; iCtr++)
    {
        ulCPUjiffies = (gpStatCPUs_2[iCtr].user - gpStatCPUs[iCtr].user) +
            (gpStatCPUs_2[iCtr].sys - gpStatCPUs[iCtr].sys) +
            (gpStatCPUs_2[iCtr].idle - gpStatCPUs[iCtr].idle);

        if (gpStatCPUs_2[iCtr].user > gpStatCPUs[iCtr].user)
        {
            sfProcPidStats->SysCPUs[iCtr].user = (((double)(gpStatCPUs_2[iCtr].user -
                gpStatCPUs[iCtr].user)) /
                ulCPUjiffies) * 100.0;
            if (sfProcPidStats->SysCPUs[iCtr].user < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].user = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].user = 0;
        }

        if (gpStatCPUs_2[iCtr].sys > gpStatCPUs[iCtr].sys)
        {
            sfProcPidStats->SysCPUs[iCtr].sys = (((double)(gpStatCPUs_2[iCtr].sys -
                gpStatCPUs[iCtr].sys)) /
                ulCPUjiffies) * 100.0;
            if (sfProcPidStats->SysCPUs[iCtr].sys < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].sys = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].sys = 0;
        }

        if (gpStatCPUs_2[iCtr].idle > gpStatCPUs[iCtr].idle)
        {
            sfProcPidStats->SysCPUs[iCtr].idle = (((double)(gpStatCPUs_2[iCtr].idle -
                gpStatCPUs[iCtr].idle)) /
                ulCPUjiffies) * 100.0;
            if (sfProcPidStats->SysCPUs[iCtr].idle < .01)
            {
                sfProcPidStats->SysCPUs[iCtr].idle = 0;
            }
        }
        else
        {
            sfProcPidStats->SysCPUs[iCtr].idle = 0;
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

