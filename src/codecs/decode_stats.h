/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef PROT_STATISTICS_H
#define PROT_STATISTICS_H

#include "layer.h"

class DecodeStatistics
{
public:
    DecodeStatistics();
    ~DecodeStatistics();

    static void reset()
    {
        protocol = TunnelType::NONE;
        curr_layer = Layer::INVALID_LAYER;
    }

protected:
    
    typedef enum class {
        NONE, GRE, IPV4, IPV6, VLAN
    } TunnelType;

    static void set_protocol(Tunneltype t, uint8_t layer)
    {
        protocol = t;
        curr_layer = layer;
    };

private:

    THREAD_LOCAL TunnelType protocol;
    THREAD_LOCAL uint8_t curr_layer;

};

#endif

