//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// signature.h author Andrew R. Baker <andrewb@sourcefire.com>

#ifndef SIGNATURE_H
#define SIGNATURE_H

// basic non-detection signature info:  gid, sid, rev, class, priority, etc.

#include <cstdint>
#include <cstdio>

struct SnortConfig;
struct OptTreeNode;
struct SFGHASH;

/* this contains a list of the URLs for various reference systems */
struct ReferenceSystemNode
{
    char* name;
    char* url;
    ReferenceSystemNode* next;
};

ReferenceSystemNode* ReferenceSystemAdd(SnortConfig*, const char*, const char*);
ReferenceSystemNode* ReferenceSystemLookup(ReferenceSystemNode*, const char*);
void ParseReferenceSystemConfig(char* args);

/* XXX: update to point to the ReferenceURLNode in the referenceURL list */
struct ReferenceNode
{
    char* id;
    ReferenceSystemNode* system;
    ReferenceNode* next;
};

ReferenceNode* AddReference(SnortConfig*, ReferenceNode**, const char*, const char*);

/* struct for rule classification */
struct ClassType
{
    // FIXIT-L type and name are backwards (name -> text, type -> name)
    char* type;      /* classification type */
    int id;          /* classification id */
    char* name;      /* "pretty" classification name */
    int priority;    /* priority */
    ClassType* next;
};

/* NOTE:  These methods can only be used during parse time */
void AddClassification(SnortConfig*, const char* type, const char* name, int priority);

ClassType* ClassTypeLookupByType(SnortConfig*, const char*);

struct ServiceInfo
{
    char* service;
    int16_t service_ordinal;
};

struct OtnKey
{
    uint32_t gid;
    uint32_t sid;
};

struct SigInfo
{
    char* message;
    ClassType* class_type;
    ReferenceNode* refs;  // FIXIT-L delete this - stored but not used
    ServiceInfo* services;

    uint32_t gid;
    uint32_t sid;
    uint32_t rev;

    uint32_t class_id;
    uint32_t priority;
    uint32_t num_services;

    bool text_rule;
};

SFGHASH* OtnLookupNew();
void OtnLookupAdd(SFGHASH*, OptTreeNode*);
OptTreeNode* OtnLookup(SFGHASH*, uint32_t gid, uint32_t sid);
void OtnLookupFree(SFGHASH*);
void OtnRemove(SFGHASH*, OptTreeNode*);

void OtnDeleteData(void* data);
void OtnFree(void* data);

OptTreeNode* GetOTN(uint32_t gid, uint32_t sid);

#endif

