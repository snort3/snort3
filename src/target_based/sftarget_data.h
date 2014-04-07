/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2006-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
 * Author: Steven Sturges
 * sftarget_data.c
 */

#ifndef SFTARGET_DATA_H
#define SFTARGET_DATA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sfip_t.h"

#define SFAT_OK 0
#define SFAT_ERROR -1
#define SFAT_BUFSZ 1024

typedef enum
{
    ATTRIBUTE_NAME,
    ATTRIBUTE_ID
} AttributeTypes;

typedef enum
{
    ATTRIBUTE_SERVICE,
    ATTRIBUTE_CLIENT
} ServiceClient;

typedef struct _MapData
{
    char s_mapvalue[SFAT_BUFSZ];
    uint32_t l_mapid;
} MapData;

typedef MapData MapEntry;

typedef struct _AttributeData
{
    AttributeTypes type;
    union
    {
        char s_value[SFAT_BUFSZ];
        uint32_t l_value;
    } value;
    int confidence;
    int16_t attributeOrdinal;
} AttributeData;

#define APPLICATION_ENTRY_PORT 0x01
#define APPLICATION_ENTRY_IPPROTO 0x02
#define APPLICATION_ENTRY_PROTO 0x04
#define APPLICATION_ENTRY_APPLICATION 0x08
#define APPLICATION_ENTRY_VERSION 0x10

typedef struct _ApplicationEntry
{
    struct _ApplicationEntry *next;

    uint16_t port;
    uint16_t ipproto;
    uint16_t protocol;

    uint8_t fields;
} ApplicationEntry;

typedef ApplicationEntry ApplicationList;

#define HOST_INFO_OS 1
#define HOST_INFO_VENDOR 2
#define HOST_INFO_VERSION 3
#define HOST_INFO_FRAG_POLICY 4
#define HOST_INFO_STREAM_POLICY 5
#define POLICY_SET 1
#define POLICY_NOT_SET 0
typedef struct _HostInfo
{
    char streamPolicyName[16];
    char fragPolicyName[16];

    uint16_t streamPolicy;
    uint16_t fragPolicy;

    char streamPolicySet;
    char fragPolicySet;
} HostInfo;

#define SFAT_SERVICE 1
#define SFAT_CLIENT 2
typedef struct _HostAttributeEntry
{
    sfip_t ipAddr;

    HostInfo hostInfo;
    ApplicationList *services;
    ApplicationList *clients;
} HostAttributeEntry;

/* Callback Functions from YACC */
#ifdef __cplusplus
extern "C" {
#endif
int SFAT_AddMapEntry(MapEntry *);
char *SFAT_LookupAttributeNameById(int id);
HostAttributeEntry * SFAT_CreateHostEntry(void);
int SFAT_AddHostEntryToMap(void);
int SFAT_SetHostIp(char *);
int SFAT_SetOSAttribute(AttributeData *data, int attribute);
int SFAT_SetOSPolicy(char *policy_name, int attribute);
ApplicationEntry * SFAT_CreateApplicationEntry(void);
int SFAT_AddApplicationData(void);
int SFAT_SetApplicationAttribute(AttributeData *data, int attribute);
void PrintAttributeData(char *prefix, AttributeData *data);
#ifdef __cplusplus
}
#endif

#endif /* SFTARGET_DATA_H */

