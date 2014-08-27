/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef SESSION_H
#define SESSION_H

#include "sfip/ipv6_port.h"

struct Packet;
class Flow;

class Session
{
public:
    virtual ~Session() { };

    virtual bool setup(Packet*) { return true; };
    virtual void update_direction(char /*dir*/, const sfip_t*, uint16_t /*port*/) { };
    virtual int process(Packet*) { return 0; };
    virtual void clear() = 0;
    virtual void cleanup() { clear(); };

protected:
    Session(Flow* f) { flow = f; };

public:
    Flow* flow;  // FIXIT-L use reference?
};

#endif

