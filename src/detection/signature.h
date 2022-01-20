//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include <string>

#include "target_based/snort_protocols.h"

namespace snort
{
class GHash;
struct SnortConfig;
}

struct OptTreeNode;

struct ReferenceSystem
{
    ReferenceSystem(const std::string& n, const char* u) : name(n), url(u) { }
    std::string name;
    std::string url;
};

const ReferenceSystem* reference_system_add(snort::SnortConfig*, const std::string&, const char* = "");

struct ReferenceNode
{
    ReferenceNode(const ReferenceSystem* sys, const std::string& id) : system(sys), id(id) { }
    const ReferenceSystem* system;
    std::string id;
};

void add_reference(snort::SnortConfig*, OptTreeNode*, const std::string& sys, const std::string& id);

struct ClassType
{
    ClassType(const char* s, const char* txt, unsigned pri, int id) :
        name(s), text(txt), priority(pri), id(id) { }

    std::string name;
    std::string text;
    unsigned priority;
    int id;
};

void add_classification(snort::SnortConfig*, const char* name, const char* text, unsigned priority);

const ClassType* get_classification(snort::SnortConfig*, const char*);

struct SignatureServiceInfo
{
    SignatureServiceInfo(const char* s, SnortProtocolId proto) :
        service(s), snort_protocol_id(proto) { }
    std::string service;
    SnortProtocolId snort_protocol_id;
};

struct OtnKey
{
    uint32_t gid;
    uint32_t sid;
};

enum Target
{ TARGET_NONE, TARGET_SRC, TARGET_DST, TARGET_MAX = TARGET_DST };

struct SigInfo
{
    std::string message;
    std::string* body = nullptr;

    std::vector<const ReferenceNode*> refs;
    std::vector<SignatureServiceInfo> services;

    const ClassType* class_type = nullptr;

    uint32_t gid = 0;
    uint32_t sid = 0;
    uint32_t rev = 0;

    uint32_t class_id = 0;
    uint32_t priority = 0;

    bool builtin = false;
    Target target = TARGET_NONE;
};

snort::GHash* OtnLookupNew();
void OtnLookupAdd(snort::GHash*, OptTreeNode*);
OptTreeNode* OtnLookup(snort::GHash*, uint32_t gid, uint32_t sid);
void OtnLookupFree(snort::GHash*);
void OtnRemove(snort::GHash*, OptTreeNode*);

OptTreeNode* GetOTN(uint32_t gid, uint32_t sid);

void dump_msg_map(const snort::SnortConfig*);
void dump_rule_deps(const snort::SnortConfig*);
void dump_rule_meta(const snort::SnortConfig*);
void dump_rule_state(const snort::SnortConfig*);

#endif

