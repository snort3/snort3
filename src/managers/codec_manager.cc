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
// codec_manager.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codec_manager.h"

#include "log/messages.h"
#include "main/snort_config.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet_manager.h"

#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;

#define DEFAULT_CODEC "unknown"

CodecManager* CodecManager::get_instance()
{
    NetworkPolicy* np = get_network_policy();
    assert(np);
    return np->cd_mgr;
}

class CodecManager::CodecApiWrapper : public PlugInterface
{
public:
    CodecApiWrapper(const CodecApi* a)
    { api = a; }

    ~CodecApiWrapper() override
    { }

    void global_init() override
    {
        if ( api->pinit )
            api->pinit();
    }

    void global_term() override
    {
        if ( api->pterm )
            api->pterm();
    }

    void thread_init() override
    {
        if ( api->tinit )
            api->tinit();
    }

    void thread_term() override
    {
        if ( api->tterm )
            api->tterm();
    }

    void instantiate(Module* m, SnortConfig*, const char*) override
    {
        get_instance()->instantiate(*this, m);
    }

public:
    const CodecApi* api;
};

//  CodecManager Private Data
THREAD_LOCAL ProtocolId CodecManager::grinder_id = ProtocolId::ETHERTYPE_NOT_SET;
THREAD_LOCAL uint8_t CodecManager::grinder = 0;

CodecManager::CodecManager()
{
    CodecManager::instantiate();
}

CodecManager::~CodecManager()
{
    for ( auto* cd : s_protocols )
    {
        if (!cd or cd == s_protocols[0])
            continue;

        CodecApiWrapper* wrap = (CodecApiWrapper*)PluginManager::get_interface(cd->get_name());
        wrap->api->dtor(cd);
    }
    if (s_protocols[0])
    {
        CodecApiWrapper* wrap = (CodecApiWrapper*)PluginManager::get_interface(s_protocols[0]->get_name());
        wrap->api->dtor(s_protocols[0]);
    }
}

PlugInterface* CodecManager::get_interface(const CodecApi* api)
{
    if (!api->ctor)
        ParseError("CodecApi ctor() for Codec %s: ctor() must be implemented", api->base.name);

    if (!api->dtor)
        ParseError("CodecApi dtor() for Codec %s: dtor() must be implemented", api->base.name);

    return new CodecApiWrapper(api);
}

/*
 * Begin search from index 1.  0 is a special case in that it is the default
 * codec and is actually a duplicate. i.e., we can find the 0 indexed
 * codec somewhere else in the array too.
 *
 * Returns: 0 on failure, index on success
 */
uint8_t CodecManager::get_codec(const char* const keyword)
{
    for ( uint8_t i = 1; i < s_protocols.size(); i++)
    {
        if (s_protocols[i])
        {
            const char* name = s_protocols[i]->get_name();
            if ( !strcmp(name, keyword) )
                return i;
        }
    }
    return 0;
}

void CodecManager::uninstall(CodecApiWrapper& wrap, std::size_t cd_id)
{
    Codec* cd = s_protocols[cd_id];
    s_protocols[cd_id] = nullptr;

    std::vector<ProtocolId> ids;
    cd->get_protocol_ids(ids);

    for (auto id : ids)
        s_proto_map[to_utype(id)] = 0;

    wrap.api->dtor(cd);
}

// we install all codecs first so that each CodecManager instance has
// the same mapping because there is only one (thread local) grinder
// so it must point to the same codec in each instance. the alternative
// is to make the grinder a slotted member (members can't have thread
// local storage class).
//
// when codecs are later instantiated by Lua, we must find the default
// instance, unmap it and remove it, and then map and install the new
// instance since it could be configured with different IDs like
// vlan.extra_tpid_ether_types.
void CodecManager::instantiate(CodecApiWrapper& wrap, Module* m)
{
    if (codec_id >= s_protocols.size())
    {
        ParseError("A maximum of 256 codecs can be registered");
        return;
    }

    Codec* cd = wrap.api->ctor(m);
    std::size_t cd_id = get_codec(cd->get_name());

    if ( cd_id )
        uninstall(wrap, cd_id);
    else
        cd_id = codec_id++;

    std::vector<ProtocolId> ids;
    cd->get_protocol_ids(ids);

    for (auto id : ids)
    {
        auto a = to_utype(id);
        auto b = (decltype(s_proto_map[a]))cd_id;

        if (s_proto_map[a] != 0)
            ParseError("The codecs %s and %s have both been registered "
                "for protocol_id 0x%X. Codec %s will be used\n",
                s_protocols[s_proto_map[to_utype(id)]]->get_name(), cd->get_name(),
                static_cast<uint16_t>(id), cd->get_name());

        s_proto_map[a] = b;
    }

    s_protocols[cd_id] = cd;
}

void CodecManager::instantiate()
{
    auto create = [](PlugInterface* pin, void* pv)
    {
        CodecApiWrapper* wrap = (CodecApiWrapper*)pin;
        ((CodecManager*)pv)->instantiate(*wrap, nullptr);
        PluginManager::set_instantiated(wrap->api->base.name);
    };

    PluginManager::for_each(PT_CODEC, create, this);

    if ( auto id = get_codec(DEFAULT_CODEC) )
        s_protocols[0] = s_protocols[id];
}

void CodecManager::thread_init()
{
    int daq_dlt = SFDAQ::get_base_protocol();

    for (int i = 0; s_protocols[i] != nullptr; i++)
    {
        Codec* cd = s_protocols[i];
        std::vector<int> data_link_types;

        cd->get_data_link_type(data_link_types);
        for (auto curr_dlt : data_link_types)
        {
            if (curr_dlt == daq_dlt)
            {
                if (grinder != 0)
                    WarningMessage("The Codecs %s and %s have both been registered "
                        "as the DLT(%i) decoder. Codec %s will be used\n",
                        s_protocols[grinder]->get_name(), cd->get_name(),
                        curr_dlt, cd->get_name());

                std::vector<ProtocolId> ids;
                s_protocols[i]->get_protocol_ids(ids);

                grinder_id = ( !ids.empty() ) ? ids[0] : ProtocolId::FINISHED_DECODE;
                grinder = (uint8_t)i;
            }
        }
    }

    if (!grinder)
        ErrorMessage("No codec found for data link type %d\n", daq_dlt);
}

void CodecManager::thread_reinit()
{
    grinder_id = ProtocolId::ETHERTYPE_NOT_SET;
    grinder = 0;
    thread_init();
}

void CodecManager::thread_term()
{
    PacketManager::accumulate(); // statistics
}

uint8_t CodecManager::get_grinder()
{
    return grinder;
}

