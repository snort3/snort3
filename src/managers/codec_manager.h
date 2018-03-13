//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// codec_manager.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef MANAGERS_CODEC_MANAGER_H
#define MANAGERS_CODEC_MANAGER_H

// Factory for Codecs.  Runtime support is provided by PacketManager.

#include <array>
#include <vector>

#include "main/thread.h"
#include "protocols/protocol_ids.h"

#ifdef PIGLET
#include "framework/codec.h"
#endif

namespace snort
{
class Codec;
struct CodecApi;
class Module;
class PacketManager;
struct ProfileStats;
struct SnortConfig;
}

//-------------------------------------------------------------------------

extern THREAD_LOCAL snort::ProfileStats decodePerfStats;

#ifdef PIGLET
struct CodecWrapper
{
    CodecWrapper(const snort::CodecApi* a, snort::Codec* p) :
        api { a }, instance { p } { }

    ~CodecWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const snort::CodecApi* api;
    snort::Codec* instance;
};
#endif

/*
 *  CodecManager class
 */
class CodecManager
{
public:
    friend class snort::PacketManager;

    // global plugin initializer
    static void add_plugin(const struct snort::CodecApi*);
    // instantiate a specific codec with a codec specific Module
    static void instantiate(const snort::CodecApi*, snort::Module*, snort::SnortConfig*);
    // instantiate any codec for which a module has not been provided.
    static void instantiate();
    // destroy all global codec related information
    static void release_plugins();
    // initialize the current threads DLT and Packet struct
    static void thread_init(snort::SnortConfig*);
    // destroy thread_local data
    static void thread_term();
    // print all of the codec plugins
    static void dump_plugins();

#ifdef PIGLET
    static CodecWrapper* instantiate(const char*, snort::Module*, snort::SnortConfig*);
#endif

    static uint8_t get_max_layers()
    { return max_layers; }

private:
    struct CodecApiWrapper;

    static std::vector<CodecApiWrapper> s_codecs;
    static std::array<ProtocolIndex, num_protocol_ids> s_proto_map;
    static std::array<snort::Codec*, UINT8_MAX> s_protocols;

    static THREAD_LOCAL ProtocolId grinder_id;
    static THREAD_LOCAL ProtocolIndex grinder;
    static THREAD_LOCAL uint8_t max_layers;

    /*
     * Private helper functions.  These are all declared here
     * because they need access to private variables.
     */

    // Private struct defined in an anonymous namespace.
    static void instantiate(CodecApiWrapper&, snort::Module*, snort::SnortConfig*);
    static CodecApiWrapper& get_api_wrapper(const snort::CodecApi* cd_api);
    static uint8_t get_codec(const char* const keyword);

#ifdef PIGLET
    static const snort::CodecApi* find_api(const char*);
#endif
};

#endif

