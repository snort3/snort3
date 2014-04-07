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
// share.h author Russ Combs <rucombs@cisco.com>

#ifndef SHARE_H
#define SHARE_H

// FIXIT remove this dependency once stuff works
// need to move below to share.cc or 
// move below data mgr calls to share.cc
// need to build dynamic plugins and on linux to verify
#include "managers/data_manager.h"

class PlugData;

class Share
{
public:
    static PlugData* acquire(const char* key)
    { return DataManager::acquire(key); };

    static void release(PlugData* p)
    { return DataManager::release(p); };
};

#endif

