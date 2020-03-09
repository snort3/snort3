//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
// Author(s):   Andrew R. Baker <andrewb@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>
#include <iostream>

#include "signature.h"

#include "hash/hash_defs.h"
#include "hash/ghash.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/util_cstring.h"

#include "treenodes.h"

using namespace snort;

//--------------------------------------------------------------------------
// reference systems
//--------------------------------------------------------------------------

const ReferenceSystem* reference_system_add(
    SnortConfig* sc, const std::string& name, const char* url)
{
    if ( !sc->alert_refs() )
        return nullptr;

    assert(!name.empty());

    ReferenceSystem* sys = new ReferenceSystem(name, url);
    sc->references[sys->name] = sys;

    return sys;
}

static const ReferenceSystem* reference_system_lookup(SnortConfig* sc, const std::string& key)
{
    const auto it = sc->references.find(key);

    if ( it != sc->references.end() )
        return it->second;

    return nullptr;
}

//--------------------------------------------------------------------------
// references
//--------------------------------------------------------------------------

void add_reference(
    SnortConfig* sc, OptTreeNode* otn, const std::string& system, const std::string& id)
{
    if ( !sc->alert_refs() )
        return;

    assert(sc and otn and !system.empty() and !id.empty());

    const ReferenceSystem* sys = reference_system_lookup(sc, system);

    if ( !sys )
        sys = reference_system_add(sc, system);

    ReferenceNode* node = new ReferenceNode(sys, id);
    otn->sigInfo.refs.push_back(node);
}

//--------------------------------------------------------------------------
// classifications
//--------------------------------------------------------------------------

void add_classification(
    SnortConfig* sc, const char* name, const char* text, unsigned priority)
{
    if ( get_classification(sc, name) )
    {
        ParseWarning(WARN_CONF, "Duplicate classification '%s' found, ignoring this line", name);
        return;
    }

    ClassType* ct = new ClassType(name, text, priority, sc->classifications.size() + 1);
    sc->classifications[ct->name] = ct;
}

const ClassType* get_classification(SnortConfig* sc, const char* type)
{
    std::string key = type;
    const auto it = sc->classifications.find(key);

    if ( it != sc->classifications.end() )
        return it->second;

    return nullptr;
}

//--------------------------------------------------------------------------
// otn utilities
//--------------------------------------------------------------------------

void OtnRemove(GHash* otn_map, OptTreeNode* otn)
{
    assert(otn_map and otn);

    OtnKey key;
    key.gid = otn->sigInfo.gid;
    key.sid = otn->sigInfo.sid;

    otn_map->remove(&key);
}

OptTreeNode::~OptTreeNode()
{
    OptFpList* opt = opt_func;

    while ( opt )
    {
        OptFpList* tmp = opt;
        opt = opt->next;
        snort_free(tmp);
    }

    for ( auto& ref : sigInfo.refs )
        delete ref;

    if ( tag )
        snort_free(tag);

    if ( soid )
        snort_free(soid);

    if (proto_nodes)
        snort_free(proto_nodes);

    if (detection_filter)
        snort_free(detection_filter);

    delete[] state;
}

static void OtnFree(void* data)
{
    OptTreeNode* otn = (OptTreeNode*)data;
    delete otn;
}

GHash* OtnLookupNew()
{
    return new GHash(10000, sizeof(OtnKey), 0, OtnFree);
}

void OtnLookupAdd(GHash* otn_map, OptTreeNode* otn)
{
    assert(otn_map);

    OtnKey key;
    key.gid = otn->sigInfo.gid;
    key.sid = otn->sigInfo.sid;

    int status = otn_map->insert(&key, otn);
    if ( status == HASH_OK )
        return;

    assert(status == HASH_INTABLE);
    ParseError("duplicate rule with same gid (%u) and sid (%u)", key.gid, key.sid);
}

OptTreeNode* OtnLookup(GHash* otn_map, uint32_t gid, uint32_t sid)
{
    assert(otn_map);

    OtnKey key;
    key.gid = gid;
    key.sid = sid;

    OptTreeNode* otn = (OptTreeNode*)otn_map->find(&key);

    return otn;
}

OptTreeNode* GetOTN(uint32_t gid, uint32_t sid)
{
    OptTreeNode* otn = OtnLookup(SnortConfig::get_conf()->otn_map, gid, sid);

    if ( !otn )
        return nullptr;

    if ( !getRtnFromOtn(otn) )
    {
        // If not configured to autogenerate and there isn't an RTN, meaning
        // this rule isn't in the current policy, return nullptr.
        return nullptr;
    }

    return otn;
}

void OtnLookupFree(GHash* otn_map)
{
    if ( otn_map )
        delete otn_map;
}

void dump_msg_map(SnortConfig* sc)
{
    GHashNode* ghn = sc->otn_map->find_first();

    while ( ghn )
    {
        const OptTreeNode* otn = (OptTreeNode*)ghn->data;
        const SigInfo& si = otn->sigInfo;

        std::cout << si.gid << " || ";
        std::cout << si.sid << " || ";
        std::cout << si.rev << " || ";
        std::cout << si.message;

        for ( const auto& rn : si.refs )
            std::cout << " || " << rn->system->name << "," << rn->id;

        std::cout << std::endl;
        ghn = sc->otn_map->find_next();
    }
}

