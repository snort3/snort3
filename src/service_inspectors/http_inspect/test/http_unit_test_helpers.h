//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_unit_test_helpers.h author Maya Dagon <mdagon@cisco.com>
// Code moved from http_transaction_test.cc, author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_UNIT_TEST_HELPERS_H
#define HTTP_UNIT_TEST_HELPERS_H

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_flow_data.h"

class HttpUnitTestSetup
{
public:
    static HttpCommon::SectionType* get_section_type(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->section_type; }
    static HttpCommon::SectionType* get_type_expected(HttpFlowData* flow_data)
        { assert(flow_data!=nullptr); return flow_data->type_expected; }
};

#endif
