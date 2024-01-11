//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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
// active at any time. the normal workflow is:
//
// 1.  start and stop are called at the beginning and end of each wire
// packet which activates and releases one context from among those
// available.
//
// 2.  during processing interrupt and complete should be called to start
// and finish processing of a generated pseudo packet. it is possible to
// interrupt pseudo packets. complete may return without doing anything if
// dependent contexts were suspended.
//
// 3.  suspend may be called to pause the current context and activate the
// prior. multiple contexts may be suspended.
//
// 4.  there is no ordering of idle contexts. busy contexts are in strict LIFO
// order. context dependency chains are maintained in depth-first order by Flow.

#include <vector>

#include "detection/ips_context_chain.h"
#include "utils/primed_allocator.h"

namespace snort
{
class Flow;
class IpsContext;
class IpsContextData;
}

// FIXIT-E add the hold to catch offloads that don't return
class ContextSwitcher
{
public:
    ~ContextSwitcher();

    void push(snort::IpsContext*);

    void start();
    void stop();
    void abort();

    snort::IpsContext* interrupt();
    snort::IpsContext* complete();

    void suspend();
    void resume(snort::IpsContext*);

    snort::IpsContext* get_context() const;
    snort::IpsContext* get_next() const;

    snort::IpsContextData* get_context_data(unsigned id) const;
    void set_context_data(unsigned id, snort::IpsContextData*) const;

    unsigned idle_count() const;
    unsigned busy_count() const;

public:
    snort::IpsContextChain non_flow_chain;

private:
    std::vector<snort::IpsContext*> idle;
    std::vector<snort::IpsContext*> busy;
    std::vector<snort::IpsContext*> contexts;
};

#endif

