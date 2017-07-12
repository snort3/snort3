//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifndef REPUTATION_INSPECT_H
#define REPUTATION_INSPECT_H

#include "flow/flow.h"

// Per-session data block containing current state
// of the Reputation preprocessor for the session.

struct ReputationData
{
    bool disabled = false;
};

class ReputationFlowData : public FlowData
{
public:
    ReputationFlowData() : FlowData(inspector_id){}

    ~ReputationFlowData() { }

    static void init()
    { inspector_id = FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    ReputationData session;
};

#endif

