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
** authors:
** Marc Norton <mnorton@sourcefire.com>
** Dan Roelker <droelker@sourcefire.com>
**
** NOTES
**   4.10.02 - Initial Checkin.  Norton
**   5.5.02  - Changed output format and added output structure for
**             easy stat printing. Roelker
**   5.29.02 - Added ICMP traffic stats and overall protocol flow
**             stats. Roelker
**  DESCRIPTION
**    The following subroutines track eand analyze the traffic flow
**  statistics.
**
**   PacketLen vs Packet Count
**   TCP-Port vs Packet Count
**   UDP-Port vs Packet Count
**   TCP High<->High Port Count
**   UDP High<->High Port Count
*/

#include "perf_flow.h"

#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "main/snort_types.h"
#include "perf_monitor.h"
#include "protocols/icmp4.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

static void DisplayFlowStats(SFFLOW_STATS* sfFlowStats);
static void WriteFlowStats(SFFLOW_STATS*, FILE*);

typedef struct _sfSingleFlowStatsKey
{
    sfip_t ipA;
    sfip_t ipB;
} sfSFSKey;

typedef struct _sfBidirectionalTrafficStats
{
    uint64_t packets_AtoB;
    uint64_t bytes_AtoB;
    uint64_t packets_BtoA;
    uint64_t bytes_BtoA;
} sfBTStats;

typedef struct _sfSingleFlowStatsValue
{
    sfBTStats trafficStats[SFS_TYPE_MAX];
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t stateChanges[SFS_STATE_MAX];
} sfSFSValue;
static int UpdateTCPFlowStats(SFFLOW* sfFlow, int sport, int dport, int len)
{
    /*
    ** Track how much data on each port, and hihg<-> high port data
    */
    /*
    if( sport < sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
    }

    if( dport < sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpDst  [ dport ]+= len;
    }

    if( sport > 1023 && dport > 1023 )
    {
        sfFlow->portTcpHigh += len;
    }
    */

    if ( sport <  1024 && dport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
    }
    else if ( dport < 1024 && sport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portTcpDst  [ dport ]+= len;
    }
    else if ( sport < 1023 && dport < 1023 )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
        sfFlow->portTcpDst  [ dport ]+= len;
    }
    else if ( sport > 1023 && dport > 1023 )
    {
        sfFlow->portTcpSrc  [ sport ]+= len;
        sfFlow->portTcpDst  [ dport ]+= len;

        sfFlow->portTcpHigh += len;
    }

    sfFlow->portTcpTotal += len;

    return 0;
}

static int UpdateUDPFlowStats(SFFLOW* sfFlow, int sport, int dport, int len)
{
    /*
     * Track how much data on each port, and hihg<-> high port data
     */
    if ( sport <  1024 && dport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
    }
    else if ( dport < 1024 && sport > 1023 ) //sfFlow->maxPortToTrack )
    {
        sfFlow->portUdpDst  [ dport ]+= len;
    }
    else if ( sport < 1023 && dport < 1023 )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
        sfFlow->portUdpDst  [ dport ]+= len;
    }
    else if ( sport > 1023 && dport > 1023 )
    {
        sfFlow->portUdpSrc  [ sport ]+= len;
        sfFlow->portUdpDst  [ dport ]+= len;

        sfFlow->portUdpHigh += len;
    }

    sfFlow->portUdpTotal += len;

    return 0;
}

static int UpdateICMPFlowStats(SFFLOW* sfFlow, int type, int len)
{
    if (type < 256)
    {
        sfFlow->typeIcmp[type] += len;
    }

    sfFlow->typeIcmpTotal += len;

    return 0;
}

/*
*   Add in stats for this packet
*
*   Packet lengths
*/
void UpdateFlowStats(SFFLOW* sfFlow, Packet* p)
{
    uint32_t len = p->pkth->caplen;

    if (p->ptrs.tcph)
        UpdateTCPFlowStats(sfFlow, p->ptrs.sp, p->ptrs.dp, len);
    else if (p->ptrs.udph)
        UpdateUDPFlowStats(sfFlow, p->ptrs.sp, p->ptrs.dp, len);
    else if (p->ptrs.icmph)
        UpdateICMPFlowStats(sfFlow, p->ptrs.icmph->type, len);

    // Track how many packets of each length
    if (len <= SF_MAX_PKT_LEN)
        sfFlow->pktLenCnt[len]++;
    else
        sfFlow->pktLenCnt[SF_MAX_PKT_LEN+1]++;

    sfFlow->pktTotal++;
    sfFlow->byteTotal += len;
}

/*
*   Analyze/Calc Stats and Display them.
*/
void ProcessFlowStats(SFFLOW* sfFlow, FILE* fh, int console)
{
    static THREAD_LOCAL SFFLOW_STATS sfFlowStats;
    int i;
    double rate, srate, drate, totperc;
    uint64_t tot;
    time_t clock;

    memset(&sfFlowStats, 0x00, sizeof(sfFlowStats));

    /*
    **  Calculate the percentage of TCP, UDP and ICMP
    **  and other traffic that consisted in the stream.
    */
    if (sfFlow->byteTotal != 0)
    {
        sfFlowStats.trafficTCP = 100.0 * (double)(sfFlow->portTcpTotal) /
            (double)(sfFlow->byteTotal);
        sfFlowStats.trafficUDP = 100.0 * (double)(sfFlow->portUdpTotal) /
            (double)(sfFlow->byteTotal);
        sfFlowStats.trafficICMP = 100.0 * (double)(sfFlow->typeIcmpTotal) /
            (double)(sfFlow->byteTotal);
        sfFlowStats.trafficOTHER = 100.0 *
            (double)((double)sfFlow->byteTotal -
            ((double)sfFlow->portTcpTotal +
            (double)sfFlow->portUdpTotal +
            (double)sfFlow->typeIcmpTotal)) / (double)sfFlow->byteTotal;
    }
    else
    {
        sfFlowStats.trafficTCP = 0;
        sfFlowStats.trafficUDP = 0;
        sfFlowStats.trafficICMP = 0;
        sfFlowStats.trafficOTHER = 0;
    }

    /*
    **  Calculate Packet percent of total pkt length
    **  distribution.
    */
    for (i=1; i<SF_MAX_PKT_LEN + 2; i++)
    {
        if ( !sfFlow->pktLenCnt[i]  )
            continue;

        rate =  100.0 * (double)(sfFlow->pktLenCnt[i]) /
            (double)(sfFlow->pktTotal);

        if (rate >= 0.1)
        {
            sfFlowStats.pktLenPercent[i] = rate;
            sfFlowStats.pktLenPercentCount++;
        }
        else
        {
            sfFlowStats.pktLenPercent[i] = 0;
        }
    }

    /*
    **  Calculate TCP port distribution by src, dst and
    **  total percentage.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = sfFlow->portTcpSrc[i]+sfFlow->portTcpDst[i];
        if (!tot)
        {
            sfFlowStats.portflowTCP.totperc[i] = 0;
            continue;
        }

        totperc = 100.0 * tot / sfFlow->portTcpTotal;

        if (totperc >= 0.1)
        {
            srate =  100.0 * (double)(sfFlow->portTcpSrc[i]) / tot;
            drate =  100.0 * (double)(sfFlow->portTcpDst[i]) / tot;

            sfFlowStats.portflowTCP.totperc[i]    = totperc;
            sfFlowStats.portflowTCP.sport_rate[i] = srate;
            sfFlowStats.portflowTCP.dport_rate[i] = drate;
            sfFlowStats.portflowTCPCount++;
        }
        else
        {
            sfFlowStats.portflowTCP.totperc[i] = 0;
        }
    }

    if (sfFlow->portTcpTotal > 0)
        sfFlowStats.portflowHighTCP = 100.0 * sfFlow->portTcpHigh / sfFlow->portTcpTotal;
    else
        sfFlowStats.portflowHighTCP = 0;

    /*
    **  Calculate UDP port processing based on src, dst and
    **  total distributions.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = sfFlow->portUdpSrc[i]+sfFlow->portUdpDst[i];
        if (!tot)
        {
            sfFlowStats.portflowUDP.totperc[i] = 0;
            continue;
        }

        totperc= 100.0 * tot / sfFlow->portUdpTotal;

        if (totperc >= 0.1)
        {
            srate =  100.0 * (double)(sfFlow->portUdpSrc[i]) / tot;
            drate =  100.0 * (double)(sfFlow->portUdpDst[i]) / tot;

            sfFlowStats.portflowUDP.totperc[i]    = totperc;
            sfFlowStats.portflowUDP.sport_rate[i] = srate;
            sfFlowStats.portflowUDP.dport_rate[i] = drate;
            sfFlowStats.portflowUDPCount++;
        }
        else
        {
            sfFlowStats.portflowUDP.totperc[i] = 0;
        }
    }

    if (sfFlow->portUdpTotal > 0)
        sfFlowStats.portflowHighUDP = 100.0 * sfFlow->portUdpHigh / sfFlow->portUdpTotal;
    else
        sfFlowStats.portflowHighUDP = 0;

    /*
    **  Calculate ICMP statistics
    */
    for (i=0; i<256; i++)
    {
        tot = sfFlow->typeIcmp[i];
        if (!tot)
        {
            sfFlowStats.flowICMP.totperc[i] = 0;
            continue;
        }

        totperc= 100.0 * tot / sfFlow->typeIcmpTotal;

        if (totperc >= 0.1)
        {
            sfFlowStats.flowICMP.totperc[i]  = totperc;
            sfFlowStats.flowICMPCount++;
        }
        else
        {
            sfFlowStats.flowICMP.totperc[i] = 0;
        }
    }

    if (sfFlow->time)
        clock = sfFlow->time;
    else
        time(&clock);

    sfFlowStats.time = clock;

    if (console)
        DisplayFlowStats(&sfFlowStats);

    if (fh)
        WriteFlowStats(&sfFlowStats, fh);
}

static void DisplayFlowStats(SFFLOW_STATS* sfFlowStats)
{
    int i;

    LogMessage("\n");
    LogMessage("=========================================\n");
    LogMessage("Protocol Byte Flows\n");
    LogMessage("=========================================\n");
    LogMessage("Protocol    %%Total\n");
    LogMessage("------------------\n");
    LogMessage("     TCP    %6.2f\n", sfFlowStats->trafficTCP);
    LogMessage("     UDP    %6.2f\n", sfFlowStats->trafficUDP);
    LogMessage("    ICMP    %6.2f\n", sfFlowStats->trafficICMP);
    LogMessage("   Other    %6.2f\n", sfFlowStats->trafficOTHER);

    LogMessage("\n");
    LogMessage("=========================================\n");
    LogMessage("Packet Length Flows\n");
    LogMessage("=========================================\n");
    LogMessage("Bytes    %%Total\n");
    LogMessage("---------------\n");
    for (i = 1; i < SF_MAX_PKT_LEN + 1; i++)
    {
        if (sfFlowStats->pktLenPercent[i] < 0.1)
            continue;

        LogMessage(" %4d    %6.2f\n", i, sfFlowStats->pktLenPercent[i]);
    }

    if (sfFlowStats->pktLenPercent[SF_MAX_PKT_LEN + 1] >= 0.1)
        LogMessage(">%4d %6.2f%%\n", SF_MAX_PKT_LEN, sfFlowStats->pktLenPercent[SF_MAX_PKT_LEN +
            1]);

    LogMessage("\n");
    LogMessage("=========================================\n");
    LogMessage("TCP Port Flows : %.2f%% of Total\n", sfFlowStats->trafficTCP);
    LogMessage("=========================================\n");
    if (sfFlowStats->portflowTCPCount || (sfFlowStats->portflowHighTCP >= 0.1))
    {
        if (sfFlowStats->portflowTCPCount)
        {
            LogMessage("Port   %%Total     %%Src     %%Dst\n");
            LogMessage("-------------------------------\n");
            for (i = 0; i <= SF_MAX_PORT; i++)
            {
                if (sfFlowStats->portflowTCP.totperc[i])
                {
                    LogMessage("%4d   %6.2f   %6.2f   %6.2f\n",
                        i, sfFlowStats->portflowTCP.totperc[i],
                        sfFlowStats->portflowTCP.sport_rate[i],
                        sfFlowStats->portflowTCP.dport_rate[i]);
                }
            }
        }

        if (sfFlowStats->portflowHighTCP >= 0.1)
        {
            if (sfFlowStats->portflowTCPCount)
                LogMessage("\n");

            LogMessage("High<->High: %.2f%%\n", sfFlowStats->portflowHighTCP);
        }
    }
    else
    {
        LogMessage("N/A\n");
    }

    LogMessage("\n");
    LogMessage("=========================================\n");
    LogMessage("UDP Port Flows : %.2f%% of Total\n", sfFlowStats->trafficUDP);
    LogMessage("=========================================\n");
    if (sfFlowStats->portflowUDPCount || (sfFlowStats->portflowHighUDP >= 0.1))
    {
        if (sfFlowStats->portflowUDPCount)
        {
            LogMessage("Port   %%Total     %%Src     %%Dst\n");
            LogMessage("-------------------------------\n");
            for (i = 0; i <= SF_MAX_PORT; i++)
            {
                if (sfFlowStats->portflowUDP.totperc[i])
                {
                    LogMessage("%4d   %6.2f   %6.2f   %6.2f\n",
                        i, sfFlowStats->portflowUDP.totperc[i],
                        sfFlowStats->portflowUDP.sport_rate[i],
                        sfFlowStats->portflowUDP.dport_rate[i]);
                }
            }
        }

        if (sfFlowStats->portflowHighUDP >= 0.1)
        {
            if (sfFlowStats->portflowUDPCount)
                LogMessage("\n");

            LogMessage("High<->High: %.2f%%\n", sfFlowStats->portflowHighUDP);
        }
    }
    else
    {
        LogMessage("N/A\n");
    }

    LogMessage("\n");
    LogMessage("=========================================\n");
    LogMessage("ICMP Type Flows : %.2f%% of Total\n", sfFlowStats->trafficICMP);
    LogMessage("=========================================\n");
    if (sfFlowStats->flowICMPCount)
    {
        LogMessage("Type     %%Total\n");
        LogMessage("---------------\n");
        for (i = 0; i < 256; i++)
        {
            if (sfFlowStats->flowICMP.totperc[i])
            {
                LogMessage(" %3d     %6.2f\n",
                    i, sfFlowStats->flowICMP.totperc[i]);
            }
        }
    }
    else
    {
        LogMessage("N/A\n");
    }

    LogMessage("\n");
}

static void WriteFlowStats(SFFLOW_STATS* sfFlowStats, FILE* fh)
{
    int i;

    if (!fh)
        return;

    fprintf(fh, "%u,", (uint32_t)sfFlowStats->time);

    fprintf(fh, "%.2f,%.2f,%.2f,%.2f,",
        sfFlowStats->trafficTCP,
        sfFlowStats->trafficUDP,
        sfFlowStats->trafficICMP,
        sfFlowStats->trafficOTHER);

    fprintf(fh, "%d,", sfFlowStats->pktLenPercentCount);
    for (i = 1; i < SF_MAX_PKT_LEN + 2; i++)
    {
        if (sfFlowStats->pktLenPercent[i])
            fprintf(fh, "%d,%.2f,", i, sfFlowStats->pktLenPercent[i]);
    }

    fprintf(fh, "%d,", sfFlowStats->portflowTCPCount);
    for (i = 0; i <= SF_MAX_PORT; i++)
    {
        if (sfFlowStats->portflowTCP.totperc[i])
        {
            fprintf(fh, "%d,%.2f,%.2f,%.2f,",
                i, sfFlowStats->portflowTCP.totperc[i],
                sfFlowStats->portflowTCP.sport_rate[i],
                sfFlowStats->portflowTCP.dport_rate[i]);
        }
    }

    fprintf(fh, "%.2f,", sfFlowStats->portflowHighTCP);

    fprintf(fh, "%d,", sfFlowStats->portflowUDPCount);
    for (i = 0; i <= SF_MAX_PORT; i++)
    {
        if (sfFlowStats->portflowUDP.totperc[i])
        {
            fprintf(fh, "%d,%.2f,%.2f,%.2f,",
                i, sfFlowStats->portflowUDP.totperc[i],
                sfFlowStats->portflowUDP.sport_rate[i],
                sfFlowStats->portflowUDP.dport_rate[i]);
        }
    }

    fprintf(fh, "%.2f,", sfFlowStats->portflowHighUDP);

    fprintf(fh, "%d,", sfFlowStats->flowICMPCount);
    for (i = 0; i < 256; i++)
    {
        if (sfFlowStats->flowICMP.totperc[i])
            fprintf(fh, "%d,%.2f,", i, sfFlowStats->flowICMP.totperc[i]);
    }

    fprintf(fh, "\n");
    fflush(fh);
}

// IMPORTANT - whatever changes you make here, please be sure
// they correspond to the WriteFlowStats() above!
void LogFlowPerfHeader(FILE* fh)
{
    if (!fh)
        return;

    fprintf(fh,
        "#%s,%s,%s,%s,%s,",
        "time",
        "trafficTCP",
        "trafficUDP",
        "trafficICMP",
        "trafficOTHER");

    // Byte flows
    fprintf(fh,
        "%s,%s,",
        "pktLenPercentCount",
        "(pktLen,pktLenPercent)*pktLenPercentCount");

    // TCP flows
    fprintf(fh,
        "%s,%s,%s,",
        "portflowTCPCount",
        "(port,portflowTCP.totperc,portflowTCP.sport_rate,portflowTCP.dport_rate)*portflowTCPCount",
        "portflowHighTCP");

    // UDP flows
    fprintf(fh,
        "%s,%s,%s,",
        "portflowUDPCount",
        "(port,portflowUDP.totperc,portflowUDP.sport_rate,portflowUDP.dport_rate)*portflowUDPCount",
        "portflowHighUDP");

    // ICMP flows
    fprintf(fh,
        "%s,%s,",
        "flowICMPCount",
        "(type,flowICMP.totperc)*flowICMPCount");

    fprintf(fh, "\n");
    fflush(fh);
}

