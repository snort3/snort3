/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// rpc_module.h author Russ Combs <rucombs@cisco.com>

#ifndef RPC_MODULE_H
#define RPC_MODULE_H

#include "framework/module.h"
#include "framework/bits.h"
#include "main/thread.h"

#define GID_RPC_DECODE 106

#define RPC_FRAG_TRAFFIC           1
#define RPC_MULTIPLE_RECORD        2
#define RPC_LARGE_FRAGSIZE         3
#define RPC_INCOMPLETE_SEGMENT     4
#define RPC_ZERO_LENGTH_FRAGMENT   5

extern THREAD_LOCAL ProfileStats rpcdecodePerfStats;

class RpcModule : public Module
{
public:
    RpcModule();

    bool set(const char*, Value&, SnortConfig*)
    { return false; };

    unsigned get_gid() const
    { return GID_RPC_DECODE; };

    const RuleMap* get_rules() const;
    ProfileStats* get_profile() const;
};

#endif

