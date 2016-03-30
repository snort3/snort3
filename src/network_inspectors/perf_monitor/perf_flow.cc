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
#include "perf_module.h"
#include "perf_monitor.h"
#include "protocols/icmp4.h"
#include "sfip/sf_ip.h"
#include "utils/util.h"

static void display_flow_stats(FlowStats* flow_stats, FILE*);
static void write_flow_stats(FlowStats*, FILE*);

static int update_tcp_flow_stats(RawFlowStats* raw_stats, int sport, int dport, int len)
{
    /*
    ** Track how much data on each port, and hihg<-> high port data
    */
    /*
    if( sport < raw_stats->maxPortToTrack )
    {
        raw_stats->port_tcp_src  [ sport ]+= len;
    }

    if( dport < raw_stats->maxPortToTrack )
    {
        raw_stats->port_tcp_dst  [ dport ]+= len;
    }

    if( sport > 1023 && dport > 1023 )
    {
        raw_stats->port_tcp_high += len;
    }
    */

    if ( sport <  1024 && dport > 1023 ) //raw_stats->maxPortToTrack )
    {
        raw_stats->port_tcp_src  [ sport ]+= len;
    }
    else if ( dport < 1024 && sport > 1023 ) //raw_stats->maxPortToTrack )
    {
        raw_stats->port_tcp_dst  [ dport ]+= len;
    }
    else if ( sport < 1023 && dport < 1023 )
    {
        raw_stats->port_tcp_src  [ sport ]+= len;
        raw_stats->port_tcp_dst  [ dport ]+= len;
    }
    else if ( sport > 1023 && dport > 1023 )
    {
        raw_stats->port_tcp_src  [ sport ]+= len;
        raw_stats->port_tcp_dst  [ dport ]+= len;

        raw_stats->port_tcp_high += len;
    }

    raw_stats->port_tcp_total += len;

    return 0;
}

static int update_udp_flow_stats(RawFlowStats* raw_stats, int sport, int dport, int len)
{
    /*
     * Track how much data on each port, and hihg<-> high port data
     */
    if ( sport <  1024 && dport > 1023 ) //raw_stats->maxPortToTrack )
    {
        raw_stats->port_udp_src  [ sport ]+= len;
    }
    else if ( dport < 1024 && sport > 1023 ) //raw_stats->maxPortToTrack )
    {
        raw_stats->port_udp_dst  [ dport ]+= len;
    }
    else if ( sport < 1023 && dport < 1023 )
    {
        raw_stats->port_udp_src  [ sport ]+= len;
        raw_stats->port_udp_dst  [ dport ]+= len;
    }
    else if ( sport > 1023 && dport > 1023 )
    {
        raw_stats->port_udp_src  [ sport ]+= len;
        raw_stats->port_udp_dst  [ dport ]+= len;

        raw_stats->port_udp_high += len;
    }

    raw_stats->port_udp_total += len;

    return 0;
}

static int update_icmp_flow_stats(RawFlowStats* raw_stats, int type, int len)
{
    if (type < 256)
    {
        raw_stats->type_icmp[type] += len;
    }

    raw_stats->type_icmp_total += len;

    return 0;
}

void update_flow_stats(RawFlowStats* raw_stats, Packet* p)
{
    uint32_t len = p->pkth->caplen;

    if (p->ptrs.tcph)
        update_tcp_flow_stats(raw_stats, p->ptrs.sp, p->ptrs.dp, len);
    else if (p->ptrs.udph)
        update_udp_flow_stats(raw_stats, p->ptrs.sp, p->ptrs.dp, len);
    else if (p->ptrs.icmph)
        update_icmp_flow_stats(raw_stats, p->ptrs.icmph->type, len);

    // Track how many packets of each length
    if (len <= MAX_PKT_LEN)
        raw_stats->pkt_len_cnt[len]++;
    else
        raw_stats->pkt_len_cnt[MAX_PKT_LEN+1]++;

    raw_stats->pkt_total++;
    raw_stats->byte_total += len;
}

void process_flow_stats(RawFlowStats* raw_stats, FILE* fh, PerfFormat format, time_t time)
{
    static THREAD_LOCAL FlowStats flow_stats;
    int i;
    double rate, srate, drate, tot_perc;
    uint64_t tot;

    memset(&flow_stats, 0x00, sizeof(flow_stats));

    /*
    **  Calculate the percentage of TCP, UDP and ICMP
    **  and other traffic that consisted in the stream.
    */
    if (raw_stats->byte_total != 0)
    {
        flow_stats.traffic_tcp = 100.0 * (double)(raw_stats->port_tcp_total) /
            (double)(raw_stats->byte_total);
        flow_stats.traffic_udp = 100.0 * (double)(raw_stats->port_udp_total) /
            (double)(raw_stats->byte_total);
        flow_stats.traffic_icmp = 100.0 * (double)(raw_stats->type_icmp_total) /
            (double)(raw_stats->byte_total);
        flow_stats.traffic_other = 100.0 *
            (double)((double)raw_stats->byte_total -
            ((double)raw_stats->port_tcp_total +
            (double)raw_stats->port_udp_total +
            (double)raw_stats->type_icmp_total)) / (double)raw_stats->byte_total;
    }
    else
    {
        flow_stats.traffic_tcp = 0;
        flow_stats.traffic_udp = 0;
        flow_stats.traffic_icmp = 0;
        flow_stats.traffic_other = 0;
    }

    /*
    **  Calculate Packet percent of total pkt length
    **  distribution.
    */
    for (i=1; i<MAX_PKT_LEN + 2; i++)
    {
        if ( !raw_stats->pkt_len_cnt[i]  )
            continue;

        rate =  100.0 * (double)(raw_stats->pkt_len_cnt[i]) /
            (double)(raw_stats->pkt_total);

        if (rate >= 0.1)
        {
            flow_stats.pkt_len_percent[i] = rate;
            flow_stats.pkt_len_percent_count++;
        }
        else
        {
            flow_stats.pkt_len_percent[i] = 0;
        }
    }

    /*
    **  Calculate TCP port distribution by src, dst and
    **  total percentage.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = raw_stats->port_tcp_src[i]+raw_stats->port_tcp_dst[i];
        if (!tot)
        {
            flow_stats.port_flow_tcp.tot_perc[i] = 0;
            continue;
        }

        tot_perc = 100.0 * tot / raw_stats->port_tcp_total;

        if (tot_perc >= 0.1)
        {
            srate =  100.0 * (double)(raw_stats->port_tcp_src[i]) / tot;
            drate =  100.0 * (double)(raw_stats->port_tcp_dst[i]) / tot;

            flow_stats.port_flow_tcp.tot_perc[i]    = tot_perc;
            flow_stats.port_flow_tcp.sport_rate[i] = srate;
            flow_stats.port_flow_tcp.dport_rate[i] = drate;
            flow_stats.port_flow_tcp_count++;
        }
        else
        {
            flow_stats.port_flow_tcp.tot_perc[i] = 0;
        }
    }

    if (raw_stats->port_tcp_total > 0)
        flow_stats.port_flow_high_tcp = 100.0 * raw_stats->port_tcp_high / raw_stats->port_tcp_total;
    else
        flow_stats.port_flow_high_tcp = 0;

    /*
    **  Calculate UDP port processing based on src, dst and
    **  total distributions.
    */
    for (i = 0; i < perfmon_config->flow_max_port_to_track; i++)
    {
        tot = raw_stats->port_udp_src[i]+raw_stats->port_udp_dst[i];
        if (!tot)
        {
            flow_stats.port_flow_udp.tot_perc[i] = 0;
            continue;
        }

        tot_perc= 100.0 * tot / raw_stats->port_udp_total;

        if (tot_perc >= 0.1)
        {
            srate =  100.0 * (double)(raw_stats->port_udp_src[i]) / tot;
            drate =  100.0 * (double)(raw_stats->port_udp_dst[i]) / tot;

            flow_stats.port_flow_udp.tot_perc[i]    = tot_perc;
            flow_stats.port_flow_udp.sport_rate[i] = srate;
            flow_stats.port_flow_udp.dport_rate[i] = drate;
            flow_stats.port_flow_udp_count++;
        }
        else
        {
            flow_stats.port_flow_udp.tot_perc[i] = 0;
        }
    }

    if (raw_stats->port_udp_total > 0)
        flow_stats.port_flow_high_udp = 100.0 * raw_stats->port_udp_high / raw_stats->port_udp_total;
    else
        flow_stats.port_flow_high_udp = 0;

    /*
    **  Calculate ICMP statistics
    */
    for (i=0; i<256; i++)
    {
        tot = raw_stats->type_icmp[i];
        if (!tot)
        {
            flow_stats.flow_icmp.tot_perc[i] = 0;
            continue;
        }

        tot_perc= 100.0 * tot / raw_stats->type_icmp_total;

        if (tot_perc >= 0.1)
        {
            flow_stats.flow_icmp.tot_perc[i]  = tot_perc;
            flow_stats.flow_icmp_count++;
        }
        else
        {
            flow_stats.flow_icmp.tot_perc[i] = 0;
        }
    }

    flow_stats.time = time;

    if (format == PERF_TEXT)
        display_flow_stats(&flow_stats, fh);

    else if (format == PERF_CSV)
        write_flow_stats(&flow_stats, fh);
}

static void display_flow_stats(FlowStats* flow_stats, FILE* fh)
{
    int i;

    LogMessage(fh, "\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "Protocol Byte Flows\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "Protocol    %%Total\n");
    LogMessage(fh, "------------------\n");
    LogMessage(fh, "     TCP    %6.2f\n", flow_stats->traffic_tcp);
    LogMessage(fh, "     UDP    %6.2f\n", flow_stats->traffic_udp);
    LogMessage(fh, "    ICMP    %6.2f\n", flow_stats->traffic_icmp);
    LogMessage(fh, "   Other    %6.2f\n", flow_stats->traffic_other);

    LogMessage(fh, "\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "Packet Length Flows\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "Bytes    %%Total\n");
    LogMessage(fh, "---------------\n");
    for (i = 1; i < MAX_PKT_LEN + 1; i++)
    {
        if (flow_stats->pkt_len_percent[i] < 0.1)
            continue;

        LogMessage(fh, " %4d    %6.2f\n", i, flow_stats->pkt_len_percent[i]);
    }

    if (flow_stats->pkt_len_percent[MAX_PKT_LEN + 1] >= 0.1)
        LogMessage(fh, ">%4d %6.2f%%\n", MAX_PKT_LEN, flow_stats->pkt_len_percent[MAX_PKT_LEN +
            1]);

    LogMessage(fh, "\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "TCP Port Flows : %.2f%% of Total\n", flow_stats->traffic_tcp);
    LogMessage(fh, "=========================================\n");
    if (flow_stats->port_flow_tcp_count || (flow_stats->port_flow_high_tcp >= 0.1))
    {
        if (flow_stats->port_flow_tcp_count)
        {
            LogMessage(fh, "Port   %%Total     %%Src     %%Dst\n");
            LogMessage(fh, "-------------------------------\n");
            for (i = 0; i <= MAX_PORT; i++)
            {
                if (flow_stats->port_flow_tcp.tot_perc[i])
                {
                    LogMessage(fh, "%4d   %6.2f   %6.2f   %6.2f\n",
                        i, flow_stats->port_flow_tcp.tot_perc[i],
                        flow_stats->port_flow_tcp.sport_rate[i],
                        flow_stats->port_flow_tcp.dport_rate[i]);
                }
            }
        }

        if (flow_stats->port_flow_high_tcp >= 0.1)
        {
            if (flow_stats->port_flow_tcp_count)
                LogMessage(fh, "\n");

            LogMessage(fh, "High<->High: %.2f%%\n", flow_stats->port_flow_high_tcp);
        }
    }
    else
    {
        LogMessage(fh, "N/A\n");
    }

    LogMessage(fh, "\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "UDP Port Flows : %.2f%% of Total\n", flow_stats->traffic_udp);
    LogMessage(fh, "=========================================\n");
    if (flow_stats->port_flow_udp_count || (flow_stats->port_flow_high_udp >= 0.1))
    {
        if (flow_stats->port_flow_udp_count)
        {
            LogMessage(fh, "Port   %%Total     %%Src     %%Dst\n");
            LogMessage(fh, "-------------------------------\n");
            for (i = 0; i <= MAX_PORT; i++)
            {
                if (flow_stats->port_flow_udp.tot_perc[i])
                {
                    LogMessage(fh, "%4d   %6.2f   %6.2f   %6.2f\n",
                        i, flow_stats->port_flow_udp.tot_perc[i],
                        flow_stats->port_flow_udp.sport_rate[i],
                        flow_stats->port_flow_udp.dport_rate[i]);
                }
            }
        }

        if (flow_stats->port_flow_high_udp >= 0.1)
        {
            if (flow_stats->port_flow_udp_count)
                LogMessage(fh, "\n");

            LogMessage(fh, "High<->High: %.2f%%\n", flow_stats->port_flow_high_udp);
        }
    }
    else
    {
        LogMessage(fh, "N/A\n");
    }

    LogMessage(fh, "\n");
    LogMessage(fh, "=========================================\n");
    LogMessage(fh, "ICMP Type Flows : %.2f%% of Total\n", flow_stats->traffic_icmp);
    LogMessage(fh, "=========================================\n");
    if (flow_stats->flow_icmp_count)
    {
        LogMessage(fh, "Type     %%Total\n");
        LogMessage(fh, "---------------\n");
        for (i = 0; i < 256; i++)
        {
            if (flow_stats->flow_icmp.tot_perc[i])
            {
                LogMessage(fh, " %3d     %6.2f\n",
                    i, flow_stats->flow_icmp.tot_perc[i]);
            }
        }
    }
    else
    {
        LogMessage(fh, "N/A\n");
    }

    LogMessage(fh, "\n");
}

static void write_flow_stats(FlowStats* flow_stats, FILE* fh)
{
    int i;

    if (!fh)
        return;

    fprintf(fh, "%ld,", (long)flow_stats->time);

    fprintf(fh, "%.2f,%.2f,%.2f,%.2f,",
        flow_stats->traffic_tcp,
        flow_stats->traffic_udp,
        flow_stats->traffic_icmp,
        flow_stats->traffic_other);

    fprintf(fh, "%d,", flow_stats->pkt_len_percent_count);
    for (i = 1; i < MAX_PKT_LEN + 2; i++)
    {
        if (flow_stats->pkt_len_percent[i])
            fprintf(fh, "%d,%.2f,", i, flow_stats->pkt_len_percent[i]);
    }

    fprintf(fh, "%d,", flow_stats->port_flow_tcp_count);
    for (i = 0; i <= MAX_PORT; i++)
    {
        if (flow_stats->port_flow_tcp.tot_perc[i])
        {
            fprintf(fh, "%d,%.2f,%.2f,%.2f,",
                i, flow_stats->port_flow_tcp.tot_perc[i],
                flow_stats->port_flow_tcp.sport_rate[i],
                flow_stats->port_flow_tcp.dport_rate[i]);
        }
    }

    fprintf(fh, "%.2f,", flow_stats->port_flow_high_tcp);

    fprintf(fh, "%d,", flow_stats->port_flow_udp_count);
    for (i = 0; i <= MAX_PORT; i++)
    {
        if (flow_stats->port_flow_udp.tot_perc[i])
        {
            fprintf(fh, "%d,%.2f,%.2f,%.2f,",
                i, flow_stats->port_flow_udp.tot_perc[i],
                flow_stats->port_flow_udp.sport_rate[i],
                flow_stats->port_flow_udp.dport_rate[i]);
        }
    }

    fprintf(fh, "%.2f,", flow_stats->port_flow_high_udp);

    fprintf(fh, "%d,", flow_stats->flow_icmp_count);
    for (i = 0; i < 256; i++)
    {
        if (flow_stats->flow_icmp.tot_perc[i])
            fprintf(fh, "%d,%.2f,", i, flow_stats->flow_icmp.tot_perc[i]);
    }

    fprintf(fh, "\n");
    fflush(fh);
}

// IMPORTANT - whatever changes you make here, please be sure
// they correspond to the WriteFlowStats() above!
void log_flow_perf_header(FILE* fh)
{
    if (!fh)
        return;

    fprintf(fh,
        "#%s,%s,%s,%s,%s,",
        "time",
        "traffic_tcp",
        "traffic_udp",
        "traffic_icmp",
        "traffic_other");

    // Byte flows
    fprintf(fh,
        "%s,%s,",
        "pkt_len_percentCount",
        "(pktLen,pkt_len_percent)*pkt_len_percentCount");

    // TCP flows
    fprintf(fh,
        "%s,%s,%s,",
        "port_flow_tcp_count",
        "(port,port_flow_tcp.tot_perc,port_flow_tcp.sport_rate,port_flow_tcp.dport_rate)*port_flow_tcp_count",
        "port_flow_high_tcp");

    // UDP flows
    fprintf(fh,
        "%s,%s,%s,",
        "port_flow_udp_count",
        "(port,port_flow_udp.tot_perc,port_flow_udp.sport_rate,port_flow_udp.dport_rate)*port_flow_udp_count",
        "port_flow_high_udp");

    // ICMP flows
    fprintf(fh,
        "%s,%s,",
        "flow_icmp_count",
        "(type,flow_icmp.tot_perc)*flow_icmp_count");

    fprintf(fh, "\n");
    fflush(fh);
}

