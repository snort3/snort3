/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      NHttpTransaction class
//

#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_transaction.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_body.h"
#include "nhttp_msg_chunk_head.h"
#include "nhttp_msg_chunk_body.h"
#include "nhttp_msg_trailer.h"

using namespace NHttpEnums;

NHttpTransaction::~NHttpTransaction() {
    delete request;
    delete status;
    delete latest_other;
    for (int k=0; k <= 1; k++) {
        delete header[k];
        delete trailer[k];
    }
}

NHttpTransaction* NHttpTransaction::attach_my_transaction(NHttpFlowData* session_data, SourceId source_id) {
    SectionType section_type = session_data->section_type[source_id];

    // If this is a request section we replace the previous transaction with a new transaction
    if (section_type == SEC_REQUEST) {
        delete session_data->transaction[SRC_CLIENT];
        session_data->transaction[SRC_CLIENT] = new NHttpTransaction;
    }
    // If this is a status section we replace the previous transaction, taking the latest request transaction if possible
    else if (section_type == SEC_STATUS) {
        delete session_data->transaction[SRC_SERVER];
        if ((session_data->type_expected[SRC_CLIENT]) && (session_data->transaction[SRC_CLIENT] != nullptr)) {
            session_data->transaction[SRC_SERVER] = session_data->transaction[SRC_CLIENT];
            session_data->transaction[SRC_CLIENT] = nullptr;
        }
        else {
            session_data->transaction[SRC_SERVER] = new NHttpTransaction;
        }
    }
    else {
        delete session_data->transaction[source_id]->latest_other;
        session_data->transaction[source_id]->latest_other = nullptr;
    }

    return session_data->transaction[source_id];
}











