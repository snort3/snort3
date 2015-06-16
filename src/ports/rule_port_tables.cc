//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include "rule_port_tables.h"

#include "port_object.h"
#include "port_table.h"
#include "parser/parser.h"
#include "utils/util.h"

#define DEFAULT_LARGE_RULE_GROUP 9

RulePortTables* PortTablesNew()
{
    RulePortTables* rpt =
        (RulePortTables*)SnortAlloc(sizeof(RulePortTables));

    /* No content rule objects */
    if ( !(rpt->tcp_nocontent = PortObjectNew()) )
        ParseAbort("ParseRulesFile nocontent PortObjectNew() failed");

    PortObjectAddPortAny(rpt->tcp_nocontent);

    if ( !(rpt->udp_nocontent = PortObjectNew()) )
        ParseAbort("ParseRulesFile nocontent PortObjectNew() failed");

    PortObjectAddPortAny(rpt->udp_nocontent);

    if ( !(rpt->icmp_nocontent = PortObjectNew()) )
        ParseAbort("ParseRulesFile nocontent PortObjectNew() failed");

    PortObjectAddPortAny(rpt->icmp_nocontent);

    if ( !(rpt->ip_nocontent = PortObjectNew()) )
        ParseAbort("ParseRulesFile nocontent PortObjectNew() failed");

    PortObjectAddPortAny(rpt->ip_nocontent);

    /* Create the Any-Any Port Objects for each protocol */
    if ( !(rpt->tcp_anyany = PortObjectNew()) )
        ParseAbort("ParseRulesFile tcp any-any PortObjectNew() failed");

    PortObjectAddPortAny(rpt->tcp_anyany);

    if ( !(rpt->udp_anyany = PortObjectNew()) )
        ParseAbort("ParseRulesFile udp any-any PortObjectNew() failed");

    PortObjectAddPortAny(rpt->udp_anyany);

    if ( !(rpt->icmp_anyany = PortObjectNew()) )
        ParseAbort("ParseRulesFile icmp any-any PortObjectNew() failed");

    PortObjectAddPortAny(rpt->icmp_anyany);

    if ( !(rpt->ip_anyany = PortObjectNew()) )
        ParseAbort("ParseRulesFile ip PortObjectNew() failed");

    PortObjectAddPortAny(rpt->ip_anyany);

    /* Create the tcp Rules PortTables */
    if ( !(rpt->tcp_src = PortTableNew()) )
        ParseAbort("ParseRulesFile tcp-src PortTableNew() failed");

    if ( !(rpt->tcp_dst = PortTableNew()) )
        ParseAbort("ParseRulesFile tcp-dst PortTableNew() failed");

    /* Create the udp Rules PortTables */
    if ( !(rpt->udp_src = PortTableNew()) )
        ParseAbort("ParseRulesFile udp-src PortTableNew() failed");

    if ( !(rpt->udp_dst = PortTableNew()) )
        ParseAbort("ParseRulesFile udp-dst PortTableNew() failed");

    /* Create the icmp Rules PortTables */
    if ( !(rpt->icmp_src = PortTableNew()) )
        ParseAbort("ParseRulesFile icmp-src PortTableNew() failed");

    if ( !(rpt->icmp_dst = PortTableNew()) )
        ParseAbort("ParseRulesFile icmp-dst PortTableNew() failed");

    /* Create the ip Rules PortTables */
    if ( !(rpt->ip_src = PortTableNew()) )
        ParseAbort("ParseRulesFile ip-src PortTableNew() failed");


    if ( !(rpt->ip_dst = PortTableNew()) )
        ParseAbort("ParseRulesFile ip-dst PortTableNew() failed");

    /*
     * someday these could be read from snort.conf, something like...
     * 'config portlist: large-rule-count <val>'
     */
    rpt->tcp_src->pt_lrc = DEFAULT_LARGE_RULE_GROUP;
    rpt->tcp_dst->pt_lrc = DEFAULT_LARGE_RULE_GROUP;
    rpt->udp_src->pt_lrc = DEFAULT_LARGE_RULE_GROUP;
    rpt->udp_dst->pt_lrc = DEFAULT_LARGE_RULE_GROUP;
    rpt->icmp_src->pt_lrc= DEFAULT_LARGE_RULE_GROUP;
    rpt->icmp_dst->pt_lrc= DEFAULT_LARGE_RULE_GROUP;
    rpt->ip_src->pt_lrc  = DEFAULT_LARGE_RULE_GROUP;
    rpt->ip_dst->pt_lrc  = DEFAULT_LARGE_RULE_GROUP;

    return rpt;
}

void PortTablesFree(RulePortTables* port_tables)
{
    if ( !port_tables )
        return;

    if (port_tables->tcp_src)
        PortTableFree(port_tables->tcp_src);

    if (port_tables->tcp_dst)
        PortTableFree(port_tables->tcp_dst);

    if (port_tables->udp_src)
        PortTableFree(port_tables->udp_src);

    if (port_tables->udp_dst)
        PortTableFree(port_tables->udp_dst);

    if (port_tables->icmp_src)
        PortTableFree(port_tables->icmp_src);

    if (port_tables->icmp_dst)
        PortTableFree(port_tables->icmp_dst);

    if (port_tables->ip_src)
        PortTableFree(port_tables->ip_src);

    if (port_tables->ip_dst)
        PortTableFree(port_tables->ip_dst);

    if (port_tables->tcp_anyany)
        PortObjectFree(port_tables->tcp_anyany);

    if (port_tables->udp_anyany)
        PortObjectFree(port_tables->udp_anyany);

    if (port_tables->icmp_anyany)
        PortObjectFree(port_tables->icmp_anyany);

    if (port_tables->ip_anyany)
        PortObjectFree(port_tables->ip_anyany);

    if (port_tables->tcp_nocontent)
        PortObjectFree(port_tables->tcp_nocontent);

    if (port_tables->udp_nocontent)
        PortObjectFree(port_tables->udp_nocontent);

    if (port_tables->icmp_nocontent)
        PortObjectFree(port_tables->icmp_nocontent);

    if (port_tables->ip_nocontent)
        PortObjectFree(port_tables->ip_nocontent);

    free(port_tables);
}

