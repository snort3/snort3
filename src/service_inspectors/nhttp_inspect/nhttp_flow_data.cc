/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
//  @brief      Flow Data object used to store session information with Streams
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_flow_data.h"
#include "nhttp_transaction.h"

using namespace NHttpEnums;

unsigned NHttpFlowData::nhttp_flow_id = 0;

NHttpFlowData::NHttpFlowData() : FlowData(nhttp_flow_id) { }

NHttpFlowData::~NHttpFlowData() {
    for (int k=0; k <= 1; k++) {
        delete[] section_buffer[k];
        delete[] chunk_buffer[k];
        delete transaction[k];
    }
    delete_pipeline();
}

void NHttpFlowData::half_reset(SourceId source_id) {
    assert((source_id == SRC_CLIENT) || (source_id == SRC_SERVER));

    version_id[source_id] = VERS__NOTPRESENT;
    method_id[source_id] = METH__NOTPRESENT;
    status_code_num[source_id] = STAT_NOTPRESENT;

    data_length[source_id] = STAT_NOTPRESENT;
    body_octets[source_id] = STAT_NOTPRESENT;
    num_chunks[source_id] = STAT_NOTPRESENT;
}

bool NHttpFlowData::add_to_pipeline(NHttpTransaction* latest) {
    assert(!pipeline_overflow && !pipeline_underflow);
    int new_back = (pipeline_back+1) % MAX_PIPELINE;
    if (new_back == pipeline_front) {
        pipeline_overflow = true;
        return false;
    }
    pipeline[pipeline_back] = latest;
    pipeline_back = new_back;
    return true;
}

NHttpTransaction* NHttpFlowData::take_from_pipeline() {
    assert(!pipeline_underflow);
    if (pipeline_back == pipeline_front) {
        return nullptr;
    }
    int old_front = pipeline_front;
    pipeline_front = (pipeline_front+1) % MAX_PIPELINE;
    return pipeline[old_front];
}

void NHttpFlowData::delete_pipeline() {
   for (int k=pipeline_front; k != pipeline_back; k = (k+1) % MAX_PIPELINE) {
       delete pipeline[k];
   }
}













