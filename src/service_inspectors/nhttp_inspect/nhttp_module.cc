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
//  @brief      Module class for NHttpInspect
//


#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "snort.h"
#include "framework/module.h"
#include "nhttp_enum.h"
#include "nhttp_module.h"

const Parameter NHttpModule::nhttpParams[] =
    {{ "test_mode", Parameter::PT_BOOL, nullptr, "false", "read HTTP messages from text file" },
     { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }};

bool NHttpModule::begin(const char*, int, SnortConfig*) {
    printf("NHttpModule begin()\n");
    test_mode = false;
    return true;
}

bool NHttpModule::end(const char*, int, SnortConfig*) {
    printf("NHttpModule end()\n");
    return true;
}

bool NHttpModule::set(const char*, Value &val, SnortConfig*) {
    printf("NHttpModule set()\n");
    if (val.is("test_mode")) {
        test_mode = val.get_bool();
        return true;
    }
    return false;
}

unsigned NHttpModule::get_gid() const {
    return GID_HTTP_CLIENT;
}

