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
//  @brief      NHttpMsgSection class declaration
//

#ifndef NHTTP_MSG_SECTION_H
#define NHTTP_MSG_SECTION_H

#include "detection/detection_util.h"
#include "nhttp_scratch_pad.h"
#include "nhttp_field.h"
#include "nhttp_flow_data.h"
#include "nhttp_transaction.h"

//-------------------------------------------------------------------------
// NHttpMsgSection class
//-------------------------------------------------------------------------

class NHttpMsgHeadShared;

class NHttpMsgSection {
public:
    virtual ~NHttpMsgSection() { if (delete_msg_on_destruct) delete[] msg_text.start; };
    virtual void analyze() = 0;                         // Minimum necessary processing for every message
    virtual void print_section(FILE *output) = 0;       // Test tool prints all derived message parts
    virtual void gen_events() = 0;                      // Converts collected information into required preprocessor events
    virtual void update_flow() = 0;                     // Manages the splitter and communication between message sections
    virtual void legacy_clients() = 0;                  // Populates the raw and normalized buffer interface used by old Snort
    virtual NHttpEnums::ProcessResult worth_detection() // What should we do with this section after processing?
       { return NHttpEnums::RES_INSPECT; };

    NHttpEnums::MethodId get_method_id() { return method_id; };

protected:
    NHttpMsgSection(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_,
       NHttpEnums::SourceId source_id_, bool buf_owner);

    // Convenience methods
    static uint32_t find_crlf(const uint8_t* buffer, int32_t length, bool wrappable);
    void print_message_title(FILE *output, const char *title) const;
    void print_message_wrapup(FILE *output) const;
    void create_event(NHttpEnums::EventSid sid);
    void legacy_request();
    void legacy_status();
    void legacy_header(bool use_trailer);
    void legacy_cookie(NHttpMsgHeadShared* header, NHttpEnums::SourceId source_id);

    const Field msg_text;

    NHttpFlowData* const session_data;
    const NHttpEnums::SourceId source_id;
    NHttpTransaction* transaction;
    const bool tcp_close;
    ScratchPad scratch_pad;

    // This is where all the derived values, extracted message parts, and normalized values are.
    // These are all scalars, buffer pointers, and buffer sizes. The actual buffers are in message buffer (raw pieces)
    // or the scratch_pad (normalized pieces).
    uint64_t infractions;
    uint64_t events_generated = 0;
    NHttpEnums::VersionId version_id;
    NHttpEnums::MethodId method_id;
    int32_t status_code_num;

private:
    const bool delete_msg_on_destruct;
};

#endif



















