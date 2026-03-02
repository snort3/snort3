//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"
#include "protocols/protocol_ids.h"

namespace snort
{
class Codec;
struct CodecApi;
class Module;
class PacketManager;
struct ProfileStats;
}

//-------------------------------------------------------------------------

extern THREAD_LOCAL snort::ProfileStats decodePerfStats;

class CodecManager
{
public:
    CodecManager();
    ~CodecManager();

    friend class snort::PacketManager;

    static class PlugInterface* get_interface(const snort::CodecApi*);
    static CodecManager* get_instance();

    void instantiate();

    void thread_init();
    void thread_reinit();
    void thread_term();

    // print all of the codec plugins
    static void dump_plugins();
    // get the current grinder
    static uint8_t get_grinder();

private:
    class CodecApiWrapper;
    std::size_t codec_id = 1;

    std::array<ProtocolIndex, num_protocol_ids> s_proto_map { 0 };
    std::array<snort::Codec*, num_protocol_idx> s_protocols { { nullptr } };

    static THREAD_LOCAL ProtocolId grinder_id;
    static THREAD_LOCAL ProtocolIndex grinder;

    void instantiate(CodecApiWrapper&, snort::Module*);
    void uninstall(CodecApiWrapper&, std::size_t);

    uint8_t get_codec(const char* const keyword);
    snort::Codec* get_codec(ProtocolIndex);
};

#ifndef CODEC_TEST
inline snort::Codec* CodecManager::get_codec(ProtocolIndex idx)
{ return s_protocols[idx]; }
#endif

#endif

