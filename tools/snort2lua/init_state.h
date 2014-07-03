/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
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
 */
// converter.h author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <fstream>
#include "conversion_state.h"
#include "util/converter.h"

#ifndef INIT_STATE_H
#define INIT_STATE_H

class InitState : public ConversionState
{
public:
    InitState(Converter* cv, LuaData* ld);
    virtual ~InitState() {};
    virtual bool convert(std::istringstream& data);

};


static inline ConversionState* init_state_ctor(Converter* cv, LuaData* ld)
{
    return new InitState(cv, ld);
}

#endif
