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
// cip_patterns.cc author Suriya Balu <subalu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cip_patterns.h"
#include "service_inspectors/cip/cip.h"
#include "utils/util.h"

using namespace snort;

void CipPatternMatchers::cip_add_enip_command(AppId app_id, uint16_t command_id)
{
    EnipCommandList* pattern = (EnipCommandList*)snort_calloc(sizeof(EnipCommandList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.command_id = command_id;

    pattern->next = enip_command_list;
    enip_command_list = pattern;
}

void CipPatternMatchers::cip_add_path(AppId app_id, uint32_t class_id, uint8_t service_id)
{
    CipPathList* pattern = (CipPathList*)snort_calloc(sizeof(CipPathList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.class_id = class_id;
    pattern->data.service_id = service_id;

    pattern->next = path_list;
    path_list = pattern;
}

void CipPatternMatchers::cip_add_set_attribute(AppId app_id, uint32_t class_id, bool is_class_instance,
    uint32_t attribute_id)
{
    CipSetAttributeList* pattern = (CipSetAttributeList*)snort_calloc(sizeof(CipSetAttributeList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.class_id = class_id;
    pattern->data.is_class_instance = is_class_instance;
    pattern->data.attribute_id = attribute_id;

    pattern->next = set_attribute_list;
    set_attribute_list = pattern;
}

void CipPatternMatchers::cip_add_connection_class(AppId app_id, uint32_t class_id)
{
    CipConnectionClassList* pattern = (CipConnectionClassList*)snort_calloc(sizeof(CipConnectionClassList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.class_id = class_id;

    pattern->next = connection_list;
    connection_list = pattern;
}

void CipPatternMatchers::cip_add_extended_symbol_service(AppId app_id, uint8_t service_id)
{
    CipServiceList* pattern = (CipServiceList*)snort_calloc(sizeof(CipServiceList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.service_id = service_id;

    pattern->next = symbol_list;
    symbol_list = pattern;
}

void CipPatternMatchers::cip_add_service(AppId app_id, uint8_t service_id)
{
    CipServiceList* pattern = (CipServiceList*)snort_calloc(sizeof(CipServiceList));
    if (!pattern)
    {
        return;
    }

    pattern->data.app_id = app_id;
    pattern->data.service_id = service_id;

    pattern->next = service_list;
    service_list = pattern;
}

static AppId match_enip_command(const EnipCommandList* enip_command_list, const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_ENIP;

    while (enip_command_list)
    {
        if (event_data->enip_command_id == enip_command_list->data.command_id)
        {
            found_app_id = enip_command_list->data.app_id;
            break;
        }

        enip_command_list = enip_command_list->next;
    }

    return found_app_id;
}

static AppId match_cip_service(const CipServiceList* service_list, const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_CIP_UNKNOWN;

    while (service_list)
    {
        if (event_data->service_id == service_list->data.service_id)
        {
            found_app_id = service_list->data.app_id;
            break;
        }

        service_list = service_list->next;
    }

    return found_app_id;
}

static AppId match_cip_path(const CipPathList* path_list, const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_CIP_UNKNOWN;

    while (path_list)
    {
        if ((event_data->class_id == path_list->data.class_id)
            and (event_data->service_id == path_list->data.service_id))
        {
            found_app_id = path_list->data.app_id;
            break;
        }

        path_list = path_list->next;
    }

    return found_app_id;
}

static AppId match_cip_set_attribute(const CipSetAttributeList* set_attribute_list, const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_CIP_UNKNOWN;

    bool is_class_instance = (event_data->instance_id == 0);

    while (set_attribute_list)
    {
        if ((event_data->class_id == set_attribute_list->data.class_id)
            and (is_class_instance == set_attribute_list->data.is_class_instance)
            and (event_data->attribute_id == set_attribute_list->data.attribute_id))
        {
            found_app_id = set_attribute_list->data.app_id;
            break;
        }

        set_attribute_list = set_attribute_list->next;
    }

    return found_app_id;
}

static AppId match_cip_connection(const CipConnectionClassList* connection_list, const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_CIP_UNKNOWN;

    while (connection_list)
    {
        if (event_data->class_id == connection_list->data.class_id)
        {
            found_app_id = connection_list->data.app_id;
            break;
        }

        connection_list = connection_list->next;
    }

    return found_app_id;
}

AppId CipPatternMatchers::get_cip_payload_id(const CipEventData* event_data)
{
    AppId found_app_id = APP_ID_CIP_UNKNOWN;

    switch (event_data->type)
    {
    case CIP_DATA_TYPE_PATH_CLASS:
        found_app_id = match_cip_path(path_list, event_data);

        if (found_app_id == APP_ID_CIP_UNKNOWN)
        {
            found_app_id = match_cip_service(service_list, event_data);
        }
        break;

    case CIP_DATA_TYPE_PATH_EXT_SYMBOL:
        found_app_id = match_cip_service(symbol_list, event_data);

        if (found_app_id == APP_ID_CIP_UNKNOWN)
        {
            found_app_id = match_cip_service(service_list, event_data);
        }
        break;

    case CIP_DATA_TYPE_SET_ATTRIBUTE:
        found_app_id = match_cip_set_attribute(set_attribute_list, event_data);

        if (found_app_id == APP_ID_CIP_UNKNOWN)
        {
            found_app_id = match_cip_service(symbol_list, event_data);

            if (found_app_id == APP_ID_CIP_UNKNOWN)
            {
                found_app_id = match_cip_service(service_list, event_data);
            }
        }
        break;

    case CIP_DATA_TYPE_CONNECTION_SAFETY:
        found_app_id = APP_ID_CIP_SAFETY;
        break;
    case CIP_DATA_TYPE_CONNECTION:
    case CIP_DATA_TYPE_IMPLICIT:
        found_app_id = match_cip_connection(connection_list, event_data);
        break;

    case CIP_DATA_TYPE_MALFORMED:
        found_app_id = APP_ID_CIP_MALFORMED;
        break;

    case CIP_DATA_TYPE_ENIP_COMMAND:
        found_app_id = match_enip_command(enip_command_list, event_data);
        break;

    default:
        break;
    }
    return found_app_id;
}

static void free_enip_command_list(EnipCommandList* enip_command_list)
{
    EnipCommandList* node;
    for (node = enip_command_list; node != nullptr; node = enip_command_list)
    {
        enip_command_list = node->next;
        snort_free(node);
    }
}

static void free_cip_path_list(CipPathList* path_list)
{
    CipPathList* node;
    for (node = path_list; node != nullptr; node = path_list)
    {
        path_list = node->next;
        snort_free(node);
    }
}

static void free_cip_set_attribute_list( CipSetAttributeList* set_attribute_list)
{
    CipSetAttributeList* node;
    for (node = set_attribute_list; node != nullptr; node = set_attribute_list)
    {
        set_attribute_list = node->next;
        snort_free(node);
    }
}

static void free_cip_connection_class_list(CipConnectionClassList* connection_list)
{
    CipConnectionClassList* node;
    for (node = connection_list; node != nullptr; node = connection_list)
    {
        connection_list = node->next;
        snort_free(node);
    }
}

static void free_cip_extended_symbol_service_list(CipServiceList* symbol_list)
{
    CipServiceList* node;
    for (node = symbol_list; node != nullptr; node = symbol_list)
    {
        symbol_list = node->next;
        snort_free(node);
    }
}

static void free_cip_service_list(CipServiceList* service_list)
{
    CipServiceList* node;
    for (node = service_list; node != nullptr; node = service_list)
    {
        service_list = node->next;
        snort_free(node);
    }
}

CipPatternMatchers::~CipPatternMatchers()
{
    free_enip_command_list(enip_command_list);
    enip_command_list = nullptr;

    free_cip_path_list(path_list);
    path_list = nullptr;

    free_cip_set_attribute_list(set_attribute_list);
    set_attribute_list = nullptr;

    free_cip_connection_class_list(connection_list);
    connection_list = nullptr;

    free_cip_extended_symbol_service_list(symbol_list);
    symbol_list = nullptr;

    free_cip_service_list(service_list);
    service_list = nullptr;
}
