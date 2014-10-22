/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// packet_manager.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef MANAGERS_CODEC_MANAGER_H
#define MANAGERS_CODEC_MANAGER_H

#include <array>
#include <vector>
#include <cstdint>

#include "main/thread.h"

struct SnortConfig;
struct CodecApi;
class Codec;
class Module;
class PacketManager;


//-------------------------------------------------------------------------

#ifdef PERF_PROFILING
struct ProfileStats;
extern THREAD_LOCAL ProfileStats decodePerfStats;
#endif

// FIXIT-H J add configurable layers. configurable ipv6 extension. Move relevent
//              decode rules into the revived DecodeModule.

static const uint16_t max_protocol_id = 65535;


/*
 *  CodecManager class
 */
class CodecManager
{
public:
    friend class PacketManager;

    // global plugin initializer. Called by LUA to add register codecs
    static void add_plugin(const struct CodecApi*);
    // instantiate a specific codec with a codec specific Module
    static void instantiate(const CodecApi*, Module*, SnortConfig*);
    // instantiate any codec for which a module has not been provided.
    static void instantiate();
    // destroy all global codec related information
    static void release_plugins();
    // initialize the current threads DLT and Packet struct
    static void thread_init();
    // destroy thread_local data
    static void thread_term();
    // print all of the codec plugins
    static void dump_plugins();

private:
    struct CodecApiWrapper;

    static std::vector<CodecApiWrapper> s_codecs;
    static std::array<uint8_t, max_protocol_id> s_proto_map;
    static std::array<Codec*, UINT8_MAX> s_protocols;
    static THREAD_LOCAL uint8_t grinder;
    static THREAD_LOCAL uint8_t max_layers;

    /*
     * Private helper functions.  These are all declared here
     * because they need access to private varaibles.
     */

    // Private struct defined in an anonymous namespace.
    static void instantiate(CodecApiWrapper&, Module*, SnortConfig*);
    static CodecApiWrapper& get_api_wrapper(const CodecApi* cd_api);
    static uint8_t get_codec(const char* const keyword);
};

#endif
