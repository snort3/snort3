//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// http_inspect_base.h author Shibin K V <shikv@cisco.com>

#ifndef HTTP_INSPECT_BASE_H
#define HTTP_INSPECT_BASE_H

#include "flow/flow.h"
#include "framework/inspector.h"
#include "main/snort_types.h"

#include "http_common.h"

class SO_PUBLIC HttpInspectBase : public snort::Inspector
{
public:
    virtual ~HttpInspectBase() override = default;
    
    virtual HttpCommon::SectionType get_type_expected(snort::Flow* flow, HttpCommon::SourceId source_id) const = 0;
    virtual void finish_h2_body(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::H2BodyState state,
        bool clear_partial_buffer) const = 0;
    virtual void set_h2_body_state(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::H2BodyState state) const = 0;
};

#endif

