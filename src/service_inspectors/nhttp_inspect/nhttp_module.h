/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      NHttpModule
//

#ifndef NHTTP_MODULE_H
#define NHTTP_MODULE_H

#include "framework/module.h"

class NHttpModule : public Module
{
public:
    NHttpModule();
    bool begin(const char*, int, SnortConfig*);
    bool end(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);
    unsigned get_gid() const;
    bool get_test_input() const { return test_input; };
    bool get_test_output() const { return test_output; };
    bool get_test_inspect() const { return test_inspect; };
private:
    static const Parameter nhttpParams[];
    static const RuleMap nhttpEvents[];
    bool test_input = false;
    bool test_output = false;
    bool test_inspect = false;
};

#endif

