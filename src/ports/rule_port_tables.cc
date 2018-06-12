//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rule_port_tables.h"

#include "log/messages.h"

#include "port_object.h"
#include "port_table.h"

#define DEFAULT_LARGE_RULE_GROUP 9

PortProto::PortProto()
{
    src = PortTableNew();
    dst = PortTableNew();

    any = PortObjectNew();
    nfp = PortObjectNew();

    if ( !src or !dst or !any or !nfp )
        snort::ParseAbort("can't allocate port structs");

   // someday these could be read from snort.conf, something like...
   // 'config portlist: large-rule-count <val>'
    src->pt_lrc = DEFAULT_LARGE_RULE_GROUP;
    dst->pt_lrc = DEFAULT_LARGE_RULE_GROUP;

    PortObjectAddPortAny(any);
    PortObjectAddPortAny(nfp);
}

PortProto::~PortProto()
{
    if (src)
        PortTableFree(src);

    if (dst)
        PortTableFree(dst);

    if (any)
        PortObjectFree(any);

    if (nfp)
        PortObjectFree(nfp);
}

RulePortTables* PortTablesNew()
{
    RulePortTables* rpt = new RulePortTables;

    if ( !(rpt->svc_any = PortObjectNew()) )
        snort::ParseAbort("ParseRulesFile udp any-any PortObjectNew() failed");

    PortObjectAddPortAny(rpt->svc_any);

    return rpt;
}

void PortTablesFree(RulePortTables* port_tables)
{
    if ( !port_tables )
        return;

    if (port_tables->svc_any)
        PortObjectFree(port_tables->svc_any);

    delete port_tables;
}

