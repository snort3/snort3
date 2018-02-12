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
// ring.h author Russ Combs <rucombs@cisco.com>

#ifndef RING_H
#define RING_H

// Simple ring implementation

#include "ring_logic.h"

template <typename T>
class Ring
{
public:
    Ring<T>(int size);
    ~Ring<T>();

    Ring<T>(const Ring<T>&) = delete;
    Ring<T>& operator=(const Ring<T>&) = delete;

    T* read();
    bool pop();

    T* write();
    bool push();

    T get(T);
    bool put(T);

    int count();
    bool full();
    bool empty();

private:
    RingLogic logic;
    T* store;
};

template <typename T>
Ring<T>::Ring (int size) : logic(size)
{
    store = new T[size];
}

template <typename T>
Ring<T>::~Ring ()
{
    delete[] store;
}

template <typename T>
T* Ring<T>::read()
{
    int ix = logic.read();
    return (ix < 0) ? nullptr : store + ix;
}

template <typename T>
T* Ring<T>::write()
{
    int ix = logic.write();
    return (ix < 0) ? nullptr : store + ix;
}

template <typename T>
bool Ring<T>::push()
{
    return logic.push();
}

template <typename T>
bool Ring<T>::pop()
{
    return logic.pop();
}

template <typename T>
T Ring<T>::get(T v)
{
    T* p = read();
    if ( !p )
        return v;
    v = *p;
    pop();
    return v;
}

template <typename T>
bool Ring<T>::put(T v)
{
    T* p = write();
    if ( !p )
        return false;
    *p = v;
    push();
    return true;
}

template <typename T>
int Ring<T>::count()
{
    return logic.count();
}

template <typename T>
bool Ring<T>::full()
{
    return logic.full();
}

template <typename T>
bool Ring<T>::empty()
{
    return logic.empty();
}

#endif

