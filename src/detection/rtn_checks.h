//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef RTN_CHECKS_H
#define RTN_CHECKS_H

namespace snort
{
    struct Packet;
}
struct RuleFpList;
struct RuleTreeNode;

// parsing
int RuleListEnd(snort::Packet*, RuleTreeNode*, RuleFpList*, int);

// detection
int CheckBidirectional(snort::Packet*, RuleTreeNode*, RuleFpList*, int);

int CheckProto(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstIP(snort::Packet*, RuleTreeNode*, RuleFpList*, int);

int CheckSrcPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortEqual(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckSrcPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int);
int CheckDstPortNotEq(snort::Packet*, RuleTreeNode*, RuleFpList*, int);

#endif

