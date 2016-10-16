//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// context_switcher.h author Russ Combs <rucombs@cisco.com>

#ifndef CONTEXT_SWITCHER_H
#define CONTEXT_SWITCHER_H

// ContextSwitcher maintains a set of contexts, only one of which can be
// active at any time.  the normal workflow is:
//
// 1.  start and stop are called at the beginning and end of each packet
// callback which activates and releases one context from among those
// available.
//
// 2.  during processing interrupt and complete should be called to start
// and finish processing of a generated pseudo packet.  it is possible to
// interrupt pseudo packets.
//
// 3.  suspend may be called to place the current context on hold and
// activate the prior.  multiple contexts may be placed on hold.
//
// 4.  there is no ordering of idle contexts.  busy contexts are in strict
// LIFO order.  contexts on hold can be resumed in any order.

#include <vector>

class IpsContext;
class IpsContextData;

class ContextSwitcher
{
public:
    ContextSwitcher(unsigned max);
    ~ContextSwitcher();

    void push(IpsContext*);
    IpsContext* pop();

    void start();
    void stop();
    void abort();

    IpsContext* interrupt();
    IpsContext* complete();

    unsigned suspend();
    void resume(unsigned suspended);

    IpsContext* get_context() const;
    IpsContext* get_context(unsigned) const;
    IpsContext* get_next() const;

    IpsContextData* get_context_data(unsigned id) const;
    void set_context_data(unsigned id, IpsContextData*) const;

    unsigned idle_count() const;
    unsigned busy_count() const;
    unsigned hold_count() const;

    bool can_hold() const
    { return idle_count() > 5; }  // FIXIT-H define appropriate const

    bool on_hold(class Flow*);

private:
    std::vector<IpsContext*> idle;
    std::vector<IpsContext*> busy;
    std::vector<IpsContext*> hold;
};

#endif

