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
// action_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef ACTION_MANAGER_H
#define ACTION_MANAGER_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "snort_types.h"
#include "framework/base_api.h"

struct ActionApi;
class IpsAction;
struct SnortConfig;

//-------------------------------------------------------------------------

class ActionManager
{
public:
    static void add_plugin(const ActionApi*);
    static void release_plugins();
    static void dump_plugins();

    static void instantiate(const ActionApi*, Module*, SnortConfig*);
    static void execute(struct Packet*);
};

#endif


