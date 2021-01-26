//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_flow.cc author Silviu Minut <sminut@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_flow.h"

#include "host_tracker/host_cache.h"

using namespace snort;
using namespace std;

RNAFlow::~RNAFlow()
{
    // Do not call remove_flow() directly on our own server and client
    // because those might be set to 0 between the null check and remove_flow().
    // Use temporaries. We still need to lock the rna flow though, but
    // this won't lead to a deadlock.
    rna_mutex.lock();
    auto serverht_loc = serverht;
    auto clientht_loc = clientht;
    rna_mutex.unlock();

    if (serverht_loc)
        serverht_loc->remove_flow(this);

    if (clientht_loc)
        clientht_loc->remove_flow(this);
}

void RNAFlow::clear_ht(HostTracker& ht)
{
    lock_guard<mutex> lck(rna_mutex);
    if (&ht == clientht.get())
        clientht = nullptr;
    else if (&ht == serverht.get())
        serverht = nullptr;
}

RnaTracker RNAFlow::get_server(const SfIp& ip)
{
    rna_mutex.lock();
    auto loc_ht = serverht;
    rna_mutex.unlock();

    if ( !loc_ht )
        loc_ht = host_cache.find(ip);

    return loc_ht;
}

RnaTracker RNAFlow::get_client(const SfIp& ip)
{
    rna_mutex.lock();
    auto loc_ht = clientht;
    rna_mutex.unlock();

    if ( !loc_ht )
        loc_ht = host_cache.find(ip);

    return loc_ht;
}

void RNAFlow::set_server(RnaTracker& ht)
{
    rna_mutex.lock();
    serverht = ht;
    rna_mutex.unlock();
}

void RNAFlow::set_client(RnaTracker& ht)
{
    rna_mutex.lock();
    clientht = ht;
    rna_mutex.unlock();
}
