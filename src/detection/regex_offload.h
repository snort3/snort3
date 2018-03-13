//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

// regex_offload.h author Russ Combs <rucombs@cisco.com>

#ifndef REGEX_OFFLOAD_H
#define REGEX_OFFLOAD_H

// RegexOffload provides an interface to fast pattern search accelerators.
// currently implemented as a simple thread offload, but will become an 
// abstract base class with true hardware offload subclasses.  for starters
// the thread offload will "cheat" and tightly interface with fp_detect but
// eventually morph into such a proper subclass as the offload api emerges.
// presently all offload is per packet thread; packet threads do not share
// offload resources.

#include <condition_variable>
#include <list>
#include <mutex>
#include <thread>

namespace snort
{
class Flow;
struct Packet;
}
struct RegexRequest;

class RegexOffload
{
public:
    RegexOffload(unsigned max);
    ~RegexOffload();

    void stop();

    unsigned count()
    { return busy.size(); }

    void put(unsigned id, snort::Packet*);
    bool get(unsigned& id);

    bool on_hold(snort::Flow*);

private:
    static void worker(RegexRequest*);

private:
    std::list<RegexRequest*> busy;
    std::list<RegexRequest*> idle;
};

#endif

