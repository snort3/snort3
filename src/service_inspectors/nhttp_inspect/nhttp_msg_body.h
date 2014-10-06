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
//  @brief      NHttpMsgBody class declaration
//

#ifndef NHTTP_MSG_BODY_H
#define NHTTP_MSG_BODY_H

#include "nhttp_msg_section.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgBody class
//-------------------------------------------------------------------------

class NHttpMsgBody : public NHttpMsgSection {
public:
    NHttpMsgBody(const uint8_t *buffer, const uint16_t buf_size, NHttpFlowData *session_data_,
       NHttpEnums::SourceId source_id_, bool buf_owner);
    void analyze();
    void print_section(FILE *output);
    void gen_events();
    void update_flow();
    void legacy_clients();

protected:
    int64_t data_length;
    int64_t body_octets;

    Field data;
};

#endif

















