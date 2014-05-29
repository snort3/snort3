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
// binder.cc author Russ Combs <rucombs@cisco.com>

#ifndef BINDER_H
#define BINDER_H

#include <string>

#include "framework/bits.h"

enum BindRole
{
    BR_EITHER,
    BR_CLIENT,
    BR_SERVER
};

enum BindAction
{
    BA_INSPECT,
    BA_ALLOW,
    BA_BLOCK
};

enum BindProto
{
    BP_ANY,
    BP_IP,
    BP_ICMP,
    BP_TCP,
    BP_UDP
};

struct Binding
{
    // when
    std::string when_id;
    std::string when_svc;
    VlanList vlans;
    std::string nets;
    BindProto proto;
    PortList ports;
    BindRole role;

    // use
    BindAction action;
    std::string use_id;
    std::string use_svc;
    std::string type;
    std::string name;
    std::string file;

    Binding()
    { role = BR_EITHER; action = BA_INSPECT; };
};

class Binder
{
public:
    static void init();
    static void term();
    static void add(Binding*);
    static void init_flow(class Flow*);
    static void init_flow(class Flow*, struct Packet*);
};

#endif

