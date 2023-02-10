//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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

// flow_uni_list.h author davis mcpherson davmchpe@cisco.com

#ifndef FLOW_UNI_LIST_H
#define FLOW_UNI_LIST_H

#include "flow.h"

class FlowUniList
{
public:

    FlowUniList()
    {
        head = new snort::Flow;
        tail = new snort::Flow;
        head->next = tail;
        tail->prev = head;
        head->prev = nullptr;
        tail->next = nullptr;
    }

    ~FlowUniList()
    {
        delete head;
        delete tail;
    }

    void link_uni(snort::Flow* flow)
    {
        flow->next = head->next;
        flow->prev = head;
        head->next->prev = flow;
        head->next = flow;
        ++count;
    }

    bool unlink_uni(snort::Flow* flow)
    {
        if ( !flow->next )
            return false;

        flow->next->prev = flow->prev;
        flow->prev->next = flow->next;
        flow->next = flow->prev = nullptr;
        --count;
        return true;
    }

    snort::Flow* get_oldest_uni()
    {
        return ( tail->prev != head ) ? tail->prev : nullptr;
    }

    snort::Flow* get_prev(snort::Flow* flow)
    {
        return ( flow->prev != head ) ? flow->prev : nullptr;
    }

    unsigned get_count() const
    { return count; }

private:
    snort::Flow* head = nullptr;
    snort::Flow* tail = nullptr;
    unsigned count = 0;

};

#endif
