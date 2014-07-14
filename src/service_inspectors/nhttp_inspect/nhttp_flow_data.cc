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

using namespace NHttpEnums;

unsigned NHttpFlowData::nhttp_flow_id = 0;

NHttpFlowData::NHttpFlowData() : FlowData(nhttp_flow_id) {}

void NHttpFlowData::halfReset(SourceId sourceId) {
    assert((sourceId == SRC_CLIENT) || (sourceId == SRC_SERVER));
    octetsExpected[sourceId] = STAT_NOTPRESENT;

    versionId[sourceId] = VERS__NOTPRESENT;
    methodId[sourceId] = METH__NOTPRESENT;
    statusCodeNum[sourceId] = STAT_NOTPRESENT;

    dataLength[sourceId] = STAT_NOTPRESENT;
    bodySections[sourceId] = STAT_NOTPRESENT;
    bodyOctets[sourceId] = STAT_NOTPRESENT;
    numChunks[sourceId] = STAT_NOTPRESENT;
    chunkSections[sourceId] = STAT_NOTPRESENT;
    chunkOctets[sourceId] = STAT_NOTPRESENT;
}


