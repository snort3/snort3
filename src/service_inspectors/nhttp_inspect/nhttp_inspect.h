//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_inspect.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_INSPECT_H
#define NHTTP_INSPECT_H

//-------------------------------------------------------------------------
// NHttpInspect class
//-------------------------------------------------------------------------

#include "log/messages.h"

#include "nhttp_enum.h"
#include "nhttp_module.h"
#include "nhttp_stream_splitter.h"

class NHttpApi;
class NHttpMsgSection;

class NHttpInspect : public Inspector
{
public:
    static THREAD_LOCAL uint8_t body_buffer[NHttpEnums::MAX_OCTETS];

    NHttpInspect(NHttpParaList params_);

    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;
    bool get_buf(unsigned, Packet*, InspectionBuffer&) override;
    bool configure(SnortConfig*) override { return true; }
    void show(SnortConfig*) override { LogMessage("NHttpInspect\n"); }
    void eval(Packet*) override { }
    void clear(Packet* p) override;
    void clear(NHttpFlowData* session_data, NHttpEnums::SourceId source_id);
    void tinit() override { }
    void tterm() override { }
    NHttpStreamSplitter* get_splitter(bool is_client_to_server) override
    {
        return new
               NHttpStreamSplitter(is_client_to_server, this);
    }
private:
    friend NHttpApi;
    friend NHttpStreamSplitter;

    bool process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
        NHttpEnums::SourceId source_id_, bool buf_owner) const;

    static THREAD_LOCAL NHttpMsgSection* latest_section;

    const NHttpParaList params;
};

#endif

