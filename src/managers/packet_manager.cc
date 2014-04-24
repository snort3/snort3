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

#include "packet_manager.h"

#include <list>
using namespace std;

#include "framework/codec.h"
#include "snort.h"
#include "thread.h"
#include "log/messages.h"
#include "packet_io/sfdaq.h"

#include "protocols/packet.h"
#include "protocols/undefined_protocols.h"


#include "time/profiler.h"


//static list<const CodecApi*> s_codecs;
//static THREAD_LOCAL decode_f grinder;

#ifdef PERF_PROFILING
THREAD_LOCAL PreprocStats decodePerfStats;
#endif

static const uint16_t max_protocol_id = 65535;
static std::array<Codec*, max_protocol_id> s_protocols;
static list<const CodecApi*> s_codecs;

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
    s_codecs.clear();
}

void PacketManager::dump_plugins()
{
    Dumper d("Codecs");

    for ( auto* p : s_codecs )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------
// grinder
//-------------------------------------------------------------------------

void PacketManager::decode(
    Packet* p, const DAQ_PktHdr_t* pkthdr, const uint8_t* pkt)
{
    PROFILE_VARS;
    int curr_prot_id, next_prot_id;
    uint16_t len, lyr_len;

    PREPROC_PROFILE_START(decodePerfStats);

    // initialize all of the relevent data to decode this packet
    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;
    len = pkthdr->caplen;
    curr_prot_id = GRINDER_ID;

    // The boolean check in this order so 
    while(curr_prot_id  >= 0 && 
            curr_prot_id < max_protocol_id &&
            s_protocols[curr_prot_id] != 0 &&
            s_protocols[curr_prot_id]->decode(pkt, len, p, lyr_len, next_prot_id))
    {


        // if we have succesfully decoded this layer, push the layer
        PacketClass::PushLayer(p, s_protocols[curr_prot_id], pkt, lyr_len);
        curr_prot_id = next_prot_id;
        next_prot_id = -1;
        len -= lyr_len;
        pkt += lyr_len;
        lyr_len = 0;
    }

    p->dsize = len;
    p->data = pkt;

    PREPROC_PROFILE_END(decodePerfStats);
}

#if 0
const CodecApi *PacketManager::get_data_link_type(int dlt)
{
    vector<int> dlt_vec;

    for ( auto* p : s_codecs )
    {
            dlt_vec.clear();
//            p->get_dlt(dlt_vec);

            for (auto *it = dlt_vec.begin(); it != dlt_vec.end(); ++it)
            {
                if (*it == dlt)
                    return p;
            }
    }

    return nullptr;
}

void PacketManager::set_grinder(void)
{
    const char* slink = NULL;
    const char* extra = NULL;

    // initialize values

    int dlt = DAQ_GetBaseProtocol();
    const CodecApi *cd_api = get_data_link_type(dlt);

    if(cd_api != nullptr)
    {
        grinder = cd_api->ctor();

        if ( !ScReadMode() || ScPcapShow() )
            LogMessage("Decoding %s\n", slink);        
    }


    FatalError("%s(%d) Could not find codec for Data Link Type %d.\n",
                     __FILE__, __LINE__, dlt);
}
#endif

void PacketManager::set_grinder(void)
{
    vector<uint16_t> proto;
    vector<int> dlt;
    bool codec_registered;

    int daq_dlt = DAQ_GetBaseProtocol();

    for ( auto* p : s_codecs )
    {
        codec_registered = false;

        if (p->ginit)
            p->ginit();

        if (p->tinit)
            p->tinit();

        // TODO:  add module
        // null check performed when plugin added.
        Codec *cd = p->ctor();


        proto.clear();
        cd->get_protocol_ids(proto);
        for (auto proto_id : proto)
        {
            if(s_protocols[proto_id] != NULL)
                WarningMessage("The Codecs %s and %s have both been registered "
                    "for protocol_id %d. Codec %s will be used\n",
                    s_protocols[proto_id]->get_name(), cd->get_name(), 
                    proto_id, cd->get_name());
            s_protocols[proto_id] = cd;
            codec_registered = true;
        }
        // add protocols to the array


        dlt.clear();
        cd->get_data_link_type(dlt);
        // set the grinder if the data link types match
        for (auto curr_dlt : dlt )
        {
           if (curr_dlt == daq_dlt)
           {
                if (s_protocols[GRINDER_ID] != NULL)
                    WarningMessage("The Codecs %s and %s have both been registered "
                        "as the raw decoder. Codec %s will be used\n",
                        s_protocols[GRINDER_ID]->get_name(), cd->get_name(), 
                        cd->get_name());

                s_protocols[GRINDER_ID] = cd;
                codec_registered = true;
            }
        }

        if (!codec_registered)
            WarningMessage("The Codec %s is never used\n", cd->get_name());
        // ERRRO:  If multiple correct grinders found.
    }



//        FatalError("Codec installation checking!!");
}


void PacketManager::dump_stats()
{
//    for ( auto* cd : s_codecs )
//        cd->sum();
}

bool PacketManager::has_codec(uint16_t cd_id)
{
    return s_protocols[cd_id] != 0;
}

