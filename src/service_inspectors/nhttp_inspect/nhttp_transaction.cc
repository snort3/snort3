//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_transaction.cc author Tom Peters <thopeter@cisco.com>

#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_transaction.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpTransaction::~NHttpTransaction()
{
    delete request;
    delete status;
    delete header[0];
    delete header[1];
    delete trailer[0];
    delete trailer[1];
    delete latest_body;
}

NHttpTransaction* NHttpTransaction::attach_my_transaction(NHttpFlowData* session_data, SourceId
    source_id)
{
    // This factory method:
    // 1. creates new transactions for all request messages and orphaned response messages
    // 2. associates requests and responses and supports pipelining
    // 3. garbage collects unneeded transactions
    // 4. returns the current transaction

    // Request section: put the old transaction in the pipeline and replace it with a new
    // transaction. If the pipeline overflows or underflows we stop using it and just delete the
    // old transaction.
    if (session_data->section_type[source_id] == SEC_REQUEST)
    {
        // When pipelining is not occurring the response should already have taken this transaction
        // and left nullptr.
        if (session_data->transaction[SRC_CLIENT] != nullptr)
        {
            if ((session_data->pipeline_overflow) || (session_data->pipeline_underflow))
            {
                delete session_data->transaction[SRC_CLIENT];
            }
            else if (!session_data->add_to_pipeline(session_data->transaction[SRC_CLIENT]))
            {
                // The pipeline is full and just overflowed.
                session_data->infractions[source_id] += INF_PARTIAL_START;
                session_data->events[source_id].create_event(EVENT_PIPELINE_MAX);
                delete session_data->transaction[SRC_CLIENT];
            }
        }
        session_data->transaction[SRC_CLIENT] = new NHttpTransaction;
    }
    // Status section: delete the current transaction and get a new one from the pipeline. If the
    // pipeline is empty check for a request-side transaction that just finished and take it. If
    // there is no transaction available then declare an underflow and create a new transaction
    // specifically for the response side.
    else if (session_data->section_type[source_id] == SEC_STATUS)
    {
        delete session_data->transaction[SRC_SERVER];
        if (session_data->pipeline_underflow)
        {
            session_data->transaction[SRC_SERVER] = new NHttpTransaction;
        }
        else if ((session_data->transaction[SRC_SERVER] = session_data->take_from_pipeline()) ==
            nullptr)
        {
            if ((session_data->transaction[SRC_CLIENT] != nullptr) &&
                (session_data->type_expected[SRC_CLIENT] == SEC_REQUEST))
            {
                session_data->transaction[SRC_SERVER] = session_data->transaction[SRC_CLIENT];
                session_data->transaction[SRC_CLIENT] = nullptr;
            }
            else
            {
                session_data->pipeline_underflow = true;
                session_data->transaction[SRC_SERVER] = new NHttpTransaction;
            }
        }
    }

    assert((source_id == SRC_SERVER) || (session_data->transaction[source_id] != nullptr));
    return session_data->transaction[source_id];
}

