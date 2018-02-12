//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// ring_logic.h author Russ Combs <rucombs@cisco.com>

#ifndef RING_LOGIC_H
#define RING_LOGIC_H

// Logic for simple ring implementation

class RingLogic
{
public:
    RingLogic(int size);

    // return next available position or -1
    int read();
    int write();

    // return true if index advanced
    bool push();
    bool pop();

    int count();
    bool full();
    bool empty();

private:
    int next(int ix)
    { return ( ++ix < sz ) ? ix : 0; }

private:
    int sz;
    volatile int rx;
    volatile int wx;
};

inline RingLogic::RingLogic(int size)
{
    sz = size;
    rx = 0;
    wx = 1;
}

inline int RingLogic::read()
{
    int nx = next(rx);
    return ( nx == wx ) ? -1 : nx;
}

inline int RingLogic::write()
{
    int nx = next(wx);
    return ( nx == rx ) ? -1 : wx;
}

inline bool RingLogic::push()
{
    int nx = next(wx);
    if ( nx == rx )
        return false;
    wx = nx;
    return true;
}

inline bool RingLogic::pop()
{
    int nx = next(rx);
    if ( nx == wx )
        return false;
    rx = nx;
    return true;
}

inline int RingLogic::count()
{
    int c = wx - rx - 1;
    if ( c < 0 )
        c += sz;
    return c;
}

inline bool RingLogic::full()
{
    return ( count() == sz );
}

inline bool RingLogic::empty()
{
    return ( count() == 0 );
}

#endif

