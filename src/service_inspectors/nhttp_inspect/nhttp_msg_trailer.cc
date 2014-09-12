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
//  @brief      NHttpMsgTrailer class analyzes HTTP chunked message trailers.
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "snort.h"
#include "nhttp_enum.h"
#include "nhttp_msg_trailer.h"

using namespace NHttpEnums;

NHttpMsgTrailer::NHttpMsgTrailer(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_,
   SourceId source_id_, bool buf_owner) :
   NHttpMsgHeadShared(buffer, buf_size, session_data_, source_id_, buf_owner)
{
   transaction->set_trailer(this, source_id);
}

void NHttpMsgTrailer::gen_events() {
    NHttpMsgHeadShared::gen_events();
}

void NHttpMsgTrailer::print_section(FILE *output) {
    NHttpMsgSection::print_message_title(output, "trailer");
    NHttpMsgHeadShared::print_headers(output);
    NHttpMsgSection::print_message_wrapup(output);
}


void NHttpMsgTrailer::update_flow() {
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
        session_data->half_reset(source_id);
    }
    else {
        session_data->type_expected[source_id] = (source_id == SRC_CLIENT) ? SEC_REQUEST : SEC_STATUS;
        session_data->half_reset(source_id);
    }
}

ProcessResult NHttpMsgTrailer::worth_detection() {
    // Do not send empty trailers to detection
    return (headers.length != STAT_NOTPRESENT) ? RES_INSPECT : RES_IGNORE;
}

// Legacy support function. Puts message fields into the buffers used by old Snort.
void NHttpMsgTrailer::legacy_clients() {
    ClearHttpBuffers();
    legacy_request();
    legacy_status();
    legacy_header(true);
}























