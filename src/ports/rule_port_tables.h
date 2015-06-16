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

// rule_port_tables.h derived from sfportobject.h by Marc Noron

#ifndef RULE_PORT_TABLES_H
#define RULE_PORT_TABLES_H

struct PortObject;
struct PortTable;

struct RulePortTables
{
    PortTable* tcp_src, * tcp_dst;
    PortTable* udp_src, * udp_dst;
    PortTable* icmp_src,* icmp_dst;
    PortTable* ip_src,  * ip_dst;

    PortObject* tcp_anyany;
    PortObject* udp_anyany;
    PortObject* icmp_anyany;
    PortObject* ip_anyany;

    PortObject* tcp_nocontent;
    PortObject* udp_nocontent;
    PortObject* icmp_nocontent;
    PortObject* ip_nocontent;
};

RulePortTables* PortTablesNew();
void PortTablesFree(RulePortTables*);

#endif

