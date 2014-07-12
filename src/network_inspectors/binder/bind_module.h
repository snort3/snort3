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

// bind_module.cc author Russ Combs <rucombs@cisco.com>

#ifndef BIND_MODULE_H
#define BIND_MODULE_H

#include <vector>

#include "framework/module.h"
#include "main/thread.h"

extern THREAD_LOCAL ProfileStats bindPerfStats;
struct Binding;

class BinderModule : public Module
{
public:
    BinderModule();
    ~BinderModule();

    bool set(const char*, Value&, SnortConfig*);
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);

    ProfileStats* get_profile() const;

    std::vector<Binding*> get_data();
private:
    Binding* work;
    std::vector<Binding*> bindings;
};

#endif

