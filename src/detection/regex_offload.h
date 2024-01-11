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

// regex_offload.h author Russ Combs <rucombs@cisco.com>

#ifndef REGEX_OFFLOAD_H
#define REGEX_OFFLOAD_H

// RegexOffload provides an interface to fast pattern search accelerators.
// There are two flavors: MPSE and thread.  The MpseRegexOffload interfaces to
// an MPSE that is capable of regex offload such as the RXP whereas
// ThreadRegexOffload implements the regex search in auxiliary threads w/o
// requiring extra MPSE instances.  presently all offload is per packet thread;
// packet threads do not share offload resources.

#include <condition_variable>
#include <list>
#include <thread>

namespace snort
{
class Flow;
struct Packet;
struct SnortConfig;
}
struct RegexRequest;

class RegexOffload
{
public:
    static RegexOffload* get_offloader(unsigned max, bool async);
    virtual ~RegexOffload();

    virtual void stop();

    virtual void put(snort::Packet*) = 0;
    virtual bool get(snort::Packet*&) = 0;

    unsigned available() const
    { return idle.size(); }

    unsigned count() const
    { return busy.size(); }

    bool on_hold(const snort::Flow*) const;

protected:
    RegexOffload(unsigned max);

protected:
    std::list<RegexRequest*> busy;
    std::list<RegexRequest*> idle;
};

class MpseRegexOffload : public RegexOffload
{
public:
    MpseRegexOffload(unsigned max);

    void put(snort::Packet*) override;
    bool get(snort::Packet*&) override;
};

class ThreadRegexOffload : public RegexOffload
{
public:
    ThreadRegexOffload(unsigned max);
    ~ThreadRegexOffload() override;

    void stop() override;

    void put(snort::Packet*) override;
    bool get(snort::Packet*&) override;

private:
    static void worker(RegexRequest*, const snort::SnortConfig*, unsigned id);
};

#endif

