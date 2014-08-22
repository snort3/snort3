/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Author(s):   Andrew R. Baker <andrewb@sourcefire.com>
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
#ifndef SIGNATURE_H
#define SIGNATURE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>

#include "hash/sfghash.h"
#include "main/snort_types.h"

struct SnortConfig;
struct OptTreeNode;

/* this contains a list of the URLs for various reference systems */
typedef struct _ReferenceSystemNode
{
    char *name;
    char *url;
    struct _ReferenceSystemNode *next;

} ReferenceSystemNode;

ReferenceSystemNode * ReferenceSystemAdd(SnortConfig*, const char*, const char*);
ReferenceSystemNode * ReferenceSystemLookup(ReferenceSystemNode *, const char *);
void ParseReferenceSystemConfig(char *args);


/* XXX: update to point to the ReferenceURLNode in the referenceURL list */
typedef struct _ReferenceNode
{
    char *id;
    ReferenceSystemNode *system;
    struct _ReferenceNode *next;

} ReferenceNode;

ReferenceNode * AddReference(SnortConfig*, ReferenceNode**, const char*, const char*);
void FPrintReference(FILE *, ReferenceNode *);

/* struct for rule classification */
typedef struct _ClassType
{
    // FIXIT-L type and name are backwards (name -> text, type -> name)
    char *type;      /* classification type */
    int id;          /* classification id */
    char *name;      /* "pretty" classification name */
    int priority;    /* priority */
    struct _ClassType *next;
} ClassType;

/* NOTE:  These methods can only be used during parse time */
void AddClassification(
    SnortConfig* sc, const char* type, const char* name, int priority);

ClassType * ClassTypeLookupByType(SnortConfig*, const char *);
ClassType * ClassTypeLookupById(SnortConfig*, int);

typedef struct _ServiceInfo
{
    char *service;
    int16_t service_ordinal;
} ServiceInfo;

struct OtnKey
{
   uint32_t gid;
   uint32_t sid;
};

typedef struct _SigInfo
{
    uint32_t generator;
    uint32_t id;
    uint32_t rev;
    uint32_t class_id;
    ClassType *classType;
    uint32_t priority;
    char *message;
    ReferenceNode *refs;
    bool text_rule;
    unsigned int num_services;
    ServiceInfo *services;
    const char *os;
} SigInfo;

SFGHASH * OtnLookupNew(void);
void OtnLookupAdd(SFGHASH *, OptTreeNode *);
OptTreeNode * OtnLookup(SFGHASH *, uint32_t gid, uint32_t sid);
void OtnLookupFree(SFGHASH *);
void OtnRemove(SFGHASH *, OptTreeNode *);

void OtnDeleteData(void *data);
void OtnFree(void *data);

#endif /* SIGNATURE */
