//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License Version 2 as
// published by the Free Software Foundation.  You may not use, modify or
// distribute this program under any other version of the GNU General
// Public License.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
// --------------------------------------------------------------------------------
// cip_patterns.h author Suriya Balu <subalu@cisco.com>

#ifndef CIP_PATTERN_H
#define CIP_PATTERN_H

#include "pub_sub/cip_events.h"
#include "application_ids.h"

struct EnipCommandData
{
    AppId app_id;
    uint16_t command_id;
} ;

struct EnipCommandList
{
    EnipCommandData data;
    struct EnipCommandList* next;
} ;

struct CipPathData
{
    AppId app_id;
    uint32_t class_id;
    uint8_t service_id;
} ;

struct CipPathList
{
    CipPathData data;
    struct CipPathList* next;
} ;

struct CipSetAttributeData
{
    AppId app_id;
    uint32_t class_id;
    bool is_class_instance;
    uint32_t attribute_id;
} ;

struct CipSetAttributeList
{
    CipSetAttributeData data;
    struct CipSetAttributeList* next;
} ;

struct CipConnectionClassData
{
    AppId app_id;
    uint32_t class_id;
} ;

struct CipConnectionClassList
{
    CipConnectionClassData data;
    struct CipConnectionClassList* next;
} ;

struct CipServiceData
{
    AppId app_id;
    uint8_t service_id;
} ;

struct CipServiceList
{
    CipServiceData data;
    struct CipServiceList* next;
} ;

class CipPatternMatchers
{
public:
    ~CipPatternMatchers();
    void cip_add_enip_command(AppId app_id, uint16_t command_id);
    void cip_add_path(AppId app_id, uint32_t class_id, uint8_t service_id);
    void cip_add_set_attribute(AppId app_id, uint32_t class_id, bool is_class_instance, uint32_t attribute_id);
    void cip_add_extended_symbol_service(AppId app_id, uint8_t service_id);
    void cip_add_service(AppId app_id, uint8_t service_id);
    void cip_add_connection_class(AppId app_id, uint32_t class_id);
    AppId get_cip_payload_id(const CipEventData* event_data);

private:
    EnipCommandList* enip_command_list = nullptr;
    CipPathList* path_list = nullptr;
    CipSetAttributeList* set_attribute_list = nullptr;
    CipConnectionClassList* connection_list = nullptr;
    CipServiceList* symbol_list = nullptr;
    CipServiceList* service_list = nullptr;
} ;

#endif  // CIP_PATTERN_H
