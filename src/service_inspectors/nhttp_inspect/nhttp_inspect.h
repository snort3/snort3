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

#ifndef NHTTP_INSPECT_H
#define NHTTP_INSPECT_H

//-------------------------------------------------------------------------
// NHttpInspect class
//-------------------------------------------------------------------------

#include "framework/inspector.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_body.h"
#include "nhttp_msg_chunk_head.h"
#include "nhttp_msg_chunk_body.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_test_manager.h"
#include "nhttp_stream_splitter.h"
#include "nhttp_test_input.h"

class NHttpApi;

class NHttpInspect : public Inspector {
public:
    NHttpInspect(bool test_input_, bool _test_output_);

    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&);
    bool get_buf(unsigned, Packet*, InspectionBuffer&);
    bool configure(SnortConfig*);
    int verify(SnortConfig*);
    void show(SnortConfig*);
    void eval(Packet*) { return; };
    bool enabled();
    void tinit() {};
    void tterm() {};
    NHttpStreamSplitter* get_splitter(bool is_client_to_server) { return new
       NHttpStreamSplitter(is_client_to_server, this); };

private:
    friend NHttpApi;
    friend NHttpStreamSplitter;

    NHttpEnums::ProcessResult process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
       NHttpEnums::SourceId source_id_, bool buf_owner);
    NHttpTestManager test_manager;
};

#endif

