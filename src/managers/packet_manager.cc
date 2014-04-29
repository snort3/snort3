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
// packet_manager.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <list>
#include <vector>
#include <cstring>
#include <mutex>
#include "packet_manager.h"
#include "framework/codec.h"
#include "snort.h"
#include "thread.h"
#include "log/messages.h"
#include "packet_io/sfdaq.h"

#include "protocols/packet.h"
#include "protocols/undefined_protocols.h"
#include "time/profiler.h"
#include "parser/parser.h"


namespace
{
struct CdGenPegs{
    PegCount total_processed = 0;
    PegCount other_codecs = 0;
    PegCount discards = 0;
};

std::vector<const char*> gen_peg_names =
{
    "total",
    "other",
    "discards"
};

const uint8_t gen_peg_size = 3;
const uint8_t stat_offset = gen_peg_size;

} // anonymous


#ifdef PERF_PROFILING
THREAD_LOCAL PreprocStats decodePerfStats;
#endif

static const uint16_t max_protocol_id = 65535;
static std::list<const CodecApi*> s_codecs;
//static std::array<Codec*, max_protocol_id> s_protocols;


static std::array<uint8_t, max_protocol_id> s_proto_map{};
static std::array<Codec*, 256> s_protocols{};
static THREAD_LOCAL uint8_t grinder = 0;

// statistics information
static THREAD_LOCAL std::array<PegCount, 256 + gen_peg_size> s_stats;
static std::array<PegCount, 256 + gen_peg_size> g_stats;
static THREAD_LOCAL CdGenPegs pkt_cnt;

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

// note that we now have multiple preproc configs saved by parser
// (s5-global, s5-tcp, ..., etc.) but just one ppapi.  that means
// we must call the config func multiple times but add only the 1st
// instance to the policy list.
static inline const CodecApi* GetApi(const char* keyword)
{
    for ( auto* p : s_codecs )
        if ( !strncasecmp(p->base.name, keyword, strlen(p->base.name)) )
            return p;
    return NULL;
}


//-------------------------------------------------------------------------
// plugins
//-------------------------------------------------------------------------


/*
 *  THIS NEEDS TO GO INTO A README!!
 *
 *  PROTOCOL ID'S By Range
 *   0    (0x0000) -   255  (0x00FF)  --> Ip protocols
 *   256  (0x0100) -  1535  (0x05FF)  -->  random protocols (teredo, gtp)
 *  1536  (0x6000) -  65536 (0xFFFF)  --> Ethertypes
 */
void PacketManager::add_plugin(const CodecApi* api)
{
    if (!api->ctor)
        FatalError("Codec %s: ctor() must be implemented.  Look at the example code for an example.\n",
                        api->base.name);      

    if (!api->dtor)
        FatalError("Codec %s: dtor() must be implemented.  Look at the example code for an example.\n",
                        api->base.name);  

    s_codecs.push_back(api);
}

void PacketManager::release_plugins()
{
    // loop through classes
    // find corresponding api
    // delete class using api and module
    // delete class from codecs_array
    // remove api pointer
    for ( auto* p : s_codecs )
    {
//        p->dtor();
        if(p->gterm)
            p->gterm();
    }
    s_codecs.clear();
}

void PacketManager::dump_plugins()
{
    Dumper d("Codecs");

    for ( auto* p : s_codecs )
        d.dump(p->base.name, p->base.version);
}

void PacketManager::instantiate(const CodecApi* cd_api, Module* m, SnortConfig* sc)
{
#if 0
    static uint16_t codec_id = 1;
    std::vector<uint16_t> ids;
    const CodecApi *p = GetApi(cd_api->base.name);

    if(!p)
        ParseError("Unknown codec: '%s'.", cd_api->base.name);

    // global init here to ensure the global policy has already been configured
    if (p->ginit)
        p->ginit();

    Codec *cd = p->ctor();
    cd->get_protocol_ids(ids);
    for (auto id : ids)
    {
        if(s_proto_map[id] != 0)
            WarningMessage("The Codecs %s and %s have both been registered "
                "for protocol_id %d. Codec %s will be used\n",
                s_protocols[s_proto_map[id]]->get_name(), cd->get_name(),
                id, cd->get_name());

        s_proto_map[id] = codec_id;
    }

    if(cd->is_default_codec())
    {
        if(s_protocols[0])
            FatalError("Only one Codec may be the registered as default, "
                "but both the %s and %s return 'true' when "
                " the function default_codec().\n",
                s_protocols[0]->get_name(), cd->get_name());
        else
            s_protocols[0] = cd;
    }

    s_protocols[codec_id++] = cd;
#endif
}

void PacketManager::instantiate()
{
    static uint16_t codec_id = 1;

    for (auto p : s_codecs)
    {
        std::vector<uint16_t> ids;

        // global init here to ensure the global policy has already been configured
        if (p->ginit)
            p->ginit();

        Codec *cd = p->ctor();
        cd->get_protocol_ids(ids);
        for (auto id : ids)
        {
            if(s_proto_map[id] != 0)
                WarningMessage("The Codecs %s and %s have both been registered "
                    "for protocol_id %d. Codec %s will be used\n",
                    s_protocols[s_proto_map[id]]->get_name(), cd->get_name(), 
                    id, cd->get_name());

            s_proto_map[id] = codec_id;
        }

        if(cd->is_default_codec())
        {
            if(s_protocols[0])
                FatalError("Only one Codec may be the registered as default, "
                           "but both the %s and %s return 'true' when "
                           " the function default_codec().\n",
                           s_protocols[0]->get_name(), cd->get_name());
            else
                s_protocols[0] = cd;
        }

        s_protocols[codec_id++] = cd;
    }
}

void PacketManager::set_grinder(void)
{
    static std::mutex init_mutex;
    init_mutex.lock();
    instantiate();
    init_mutex.unlock();


    for ( auto* p : s_codecs )
        if (p->tinit)
            p->tinit();

    int daq_dlt = DAQ_GetBaseProtocol();
    for(int i = 0; s_protocols[i] != 0; i++)
    {
        Codec *cd = s_protocols[i];
        std::vector<int> data_link_types;

        cd->get_data_link_type(data_link_types);
        for (auto curr_dlt : data_link_types)
        {
           if (curr_dlt == daq_dlt)
           {
                if (grinder != 0)
                    WarningMessage("The Codecs %s and %s have both been registered "
                        "as the raw decoder. Codec %s will be used\n",
                        s_protocols[grinder]->get_name(), cd->get_name(),
                        cd->get_name());

                grinder = i;
            }
        }
    }

    if(!grinder)
        FatalError("Unable to find a Codec with data link type %d!!\n", daq_dlt);
}

void PacketManager::thread_term()
{
    for ( auto* p : s_codecs )
    {
        if(p->tterm)
            p->tterm();
    }

    accumulate();
}

void PacketManager::dump_stats()
{
    std::vector<const char*> pkt_names;
    pkt_names.resize(max_protocol_id + stat_offset);

    for(int i = 0; i < gen_peg_names.size(); i++)
        pkt_names[i] = gen_peg_names[i];


    for (int i = 0; i < max_protocol_id; i++)
        if(s_protocols[i])
            pkt_names[i + stat_offset] = s_protocols[i]->get_name();

    show_percent_stats((PegCount*) &g_stats, &pkt_names[0], (unsigned int) pkt_names.size(),
        "codecs");
}

void PacketManager::accumulate()
{
    static std::mutex stats_mutex;
    stats_mutex.lock();

    s_stats[0] = pkt_cnt.total_processed;
    s_stats[1] = pkt_cnt.other_codecs;
    s_stats[2] = pkt_cnt.discards;

    sum_stats(&g_stats[0], &s_stats[0], s_stats.size());

    stats_mutex.unlock();
}

//-------------------------------------------------------------------------
// grinder
//-------------------------------------------------------------------------

void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    PROFILE_VARS;
    uint16_t mapped_prot, next_prot_id;
    uint16_t len, lyr_len;

    PREPROC_PROFILE_START(decodePerfStats);

    // initialize all of the relevent data to decode this packet
    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;
    len = pkthdr->caplen;
    mapped_prot = grinder;
    pkt_cnt.total_processed++;

    // loop until the protocol id is no longer valid
    while(s_protocols[mapped_prot]->decode(pkt, len, p, lyr_len, next_prot_id))
    {
        mapped_prot =  s_proto_map[next_prot_id];
        PacketClass::PushLayer(p, s_protocols[mapped_prot], pkt, lyr_len);
        s_stats[mapped_prot + stat_offset]++;
        len -= lyr_len;
        pkt += lyr_len;
        next_prot_id = FINISHED_DECODE; // necessary in case decode returns true an
        lyr_len = 0;
    }

    p->dsize = len;
    p->data = pkt;
    PREPROC_PROFILE_END(decodePerfStats);
}

bool PacketManager::has_codec(uint16_t cd_id)
{
    return s_protocols[cd_id] != 0;
}

