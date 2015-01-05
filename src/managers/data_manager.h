/*
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// data_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef DATA_MANAGER_H
#define DATA_MANAGER_H

#include "main/snort_types.h"
#include "framework/plug_data.h"

struct SnortConfig;

class DataManager
{
public:
    static void add_plugin(const DataApi* api);
    static void dump_plugins(void);
    static void release_plugins(void);

    static void instantiate(const DataApi*, Module*, SnortConfig*);
    static PlugData* get_data(const char* key, SnortConfig*);

    SO_PUBLIC static PlugData* acquire(const char* key, SnortConfig*);
    SO_PUBLIC static void release(PlugData*);
};

#endif

