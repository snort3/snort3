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
#include "sfip/sf_ipvar.h"

class Flow;

enum BindRole
{
    BR_EITHER,
    BR_CLIENT,
    BR_SERVER
};

enum BindAction
{
    BA_BLOCK = 1,
    BA_ALLOW,
    BA_INSPECT
};

struct BindWhen
{
    unsigned id;
    std::string svc;
    VlanList vlans;
    sfip_var_t* nets;
    unsigned protos;
    PortList ports;
    BindRole role;
};

struct BindUse
{
    BindAction action;
    std::string svc;
    std::string type;
    std::string name;
    std::string file;
};

struct Binding
{
    BindWhen when;
    BindUse use;

    Binding();
    ~Binding();

    bool check_port(const Flow*) const;
    bool check_vlan(const Flow*) const;
    bool check_addr(const Flow*) const;
    bool check_proto(const Flow*) const;
    bool check_policy(const Flow*) const;
    bool check_service(const Flow*) const;
};

#endif

