//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// client_discovery.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client_discovery.h"

#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "app_info_table.h"
#include "appid_debug.h"
#include "appid_session.h"
#include "client_app_bit_tracker.h"
#include "client_app_bit.h"
#include "client_app_msn.h"
#include "client_app_rtp.h"
#include "client_app_timbuktu.h"
#include "client_app_tns.h"
#include "client_app_vnc.h"
#include "detector_plugins/detector_imap.h"
#include "detector_plugins/detector_kerberos.h"
#include "detector_plugins/detector_pattern.h"
#include "detector_plugins/detector_pop3.h"
#include "detector_plugins/detector_sip.h"
#include "detector_plugins/detector_smtp.h"

using namespace snort;

#define MAX_CANDIDATE_CLIENTS 10

void ClientDiscovery::initialize(AppIdInspector& inspector)
{
    new BitClientDetector(this);
    new BitTrackerClientDetector(this);
    new ImapClientDetector(this);
    new KerberosClientDetector(this);
    new MsnClientDetector(this);
    new Pop3ClientDetector(this);
    new RtpClientDetector(this);
    new SipTcpClientDetector(this);
    new SipUdpClientDetector(this);
    new SmtpClientDetector(this);
    new TimbuktuClientDetector(this);
    new TnsClientDetector(this);
    new VncClientDetector(this);

    for ( auto& kv : tcp_detectors )
        kv.second->initialize(inspector);

    for ( auto& kv : udp_detectors )
        kv.second->initialize(inspector);
}

void ClientDiscovery::reload()
{
    for ( auto& kv : tcp_detectors )
        kv.second->do_custom_reload();
    for ( auto& kv : udp_detectors )
        kv.second->do_custom_reload();
}

void ClientDiscovery::finalize_client_patterns()
{
    tcp_patterns.prep();
    udp_patterns.prep();
}

void ClientDiscovery::reload_client_patterns()
{
    tcp_patterns.reload();
    udp_patterns.reload();
}

unsigned ClientDiscovery::get_pattern_count()
{
    return tcp_pattern_count + udp_pattern_count;
}

ClientDetector* ClientDiscovery::get_client_detector(const std::string& name) const
{
    auto det = tcp_detectors.find(name);
    if (det != tcp_detectors.end())
        return (ClientDetector*) det->second;

    return nullptr;
}

/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from pop_config.cmds
 * @param   index   index in array of search strings from pop_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
static int pattern_match(void* id, void* /*unused_tree*/, int match_end_pos, void* data,
    void* /*unused_neg*/)
{
    ClientAppMatch** matches = (ClientAppMatch**)data;
    AppIdPatternMatchNode* pd = (AppIdPatternMatchNode*)id;

    if ( pd->valid_match(match_end_pos) )
    {
        ClientAppMatch* cam;

        for (cam = *matches; cam; cam = cam->next)
            if (cam->detector == pd->service)
                break;

        if (cam)
            cam->count++;
        else
        {
            cam = (ClientAppMatch*)snort_alloc(sizeof(ClientAppMatch));

            cam->count = 1;
            cam->detector =  static_cast<const ClientDetector*>(pd->service);
            cam->next = *matches;
            *matches = cam;
        }
    }

    return 0;
}

static const ClientDetector* get_next_detector(ClientAppMatch** match_list)
{
    ClientAppMatch* curr;
    ClientAppMatch* prev = nullptr;
    ClientAppMatch* max_curr = nullptr;
    ClientAppMatch* max_prev = nullptr;
    unsigned max_count;
    unsigned max_precedence;

    curr = *match_list;
    max_count = 0;
    max_precedence = 0;
    while (curr)
    {
        if (curr->count >= curr->detector->get_minimum_matches()
            && ((curr->count > max_count)
            || (curr->count == max_count && curr->detector->get_precedence() > max_precedence)))
        {
            max_count = curr->count;
            max_precedence = curr->detector->get_precedence();
            max_curr = curr;
            max_prev = prev;
        }
        prev = curr;
        curr = curr->next;
    }

    if (max_curr != nullptr)
    {
        if (max_prev == nullptr)
            *match_list = (*match_list)->next;
        else
            max_prev->next = max_curr->next;

        const ClientDetector* detector = max_curr->detector;
        snort_free(max_curr);
        return detector;
    }
    else
        return nullptr;
}

static void free_matched_list(ClientAppMatch** match_list)
{
    ClientAppMatch* cam;
    ClientAppMatch* tmp;

    cam = *match_list;
    while (cam)
    {
        tmp = cam;
        cam = tmp->next;
        snort_free(tmp);
    }

    *match_list = nullptr;
}

ClientAppMatch* ClientDiscovery::find_detector_candidates(const Packet* pkt, const AppIdSession& asd)
{
    ClientAppMatch* match_list = nullptr;
    SearchTool* patterns;

    if (asd.protocol == IpProtocol::TCP)
        patterns = &asd.get_odp_ctxt().get_client_disco_mgr().tcp_patterns;
    else
        patterns = &asd.get_odp_ctxt().get_client_disco_mgr().udp_patterns;

    if ( patterns )
        patterns->find_all((const char*)pkt->data, pkt->dsize, &pattern_match, false, (void*)&match_list);

    return match_list;
}

void ClientDiscovery::create_detector_candidates_list(AppIdSession& asd, Packet* p)
{
    ClientAppMatch* match_list;

    if ( !p->dsize || asd.client_detector != nullptr || !asd.client_candidates.empty() )
        return;

    match_list = find_detector_candidates(p, asd);
    while ( asd.client_candidates.size() < MAX_CANDIDATE_CLIENTS )
    {
        ClientDetector* cd = const_cast<ClientDetector*>(get_next_detector(&match_list));
        if (!cd)
            break;

        if ( asd.client_candidates.find(cd->get_name()) == asd.client_candidates.end() )
            asd.client_candidates[cd->get_name()] = cd;
    }

    free_matched_list(&match_list);
}

int ClientDiscovery::get_detector_candidates_list(AppIdSession& asd, Packet* p, AppidSessionDirection direction)
{
    if (direction == APP_ID_FROM_INITIATOR)
    {
        /* get out if we've already tried to validate a client app */
        if ( !asd.is_client_detected() )
            create_detector_candidates_list(asd, p);
    }
    else if ( asd.service_disco_state != APPID_DISCO_STATE_STATEFUL
        && asd.get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS) )
        create_detector_candidates_list(asd, p);

    return 0;
}

// This function sets the client discovery state to APPID_DISCO_STATE_FINISHED
// on anything the client candidates return (including e.g. APPID_ENULL, etc.),
// except on APPID_INPROCESS, in which case the discovery state remains unchanged.
void ClientDiscovery::exec_client_detectors(AppIdSession& asd, Packet* p,
    AppidSessionDirection direction, AppidChangeBits& change_bits)
{
    int ret = APPID_INPROCESS;

    if (asd.client_detector != nullptr)
    {
        AppIdDiscoveryArgs disco_args(p->data, p->dsize, direction, asd, p, change_bits);
        ret = asd.client_detector->validate(disco_args);
        appid_log(p, TRACE_DEBUG_LEVEL, "%s client detector returned %s (%d)\n",
            asd.client_detector->get_log_name().c_str(),
            asd.client_detector->get_code_string((APPID_STATUS_CODE)ret), ret);
    }
    else
    {
        for ( auto kv = asd.client_candidates.begin(); kv != asd.client_candidates.end(); )
        {
            AppIdDiscoveryArgs disco_args(p->data, p->dsize, direction, asd, p, change_bits);
            int result = kv->second->validate(disco_args);
            appid_log(p, TRACE_DEBUG_LEVEL, "%s client candidate returned %s (%d)\n",
                kv->second->get_log_name().c_str(),
                kv->second->get_code_string((APPID_STATUS_CODE)result), result);

            if (result == APPID_SUCCESS)
            {
                asd.client_detector = kv->second;
                asd.client_candidates.clear();
                break;
            }
            else if (result != APPID_INPROCESS)
                kv = asd.client_candidates.erase(kv);
            else
                ++kv;
        }

        // At this point, candidates that have survived must have returned
        // either APPID_SUCCESS or APPID_INPROCESS. The others got removed
        // from the candidates list. If the list is empty, say we're done.
        if (asd.client_candidates.empty())
        {
            ret = APPID_SUCCESS;
            asd.set_client_detected();
        }
    }

    if (ret != APPID_INPROCESS)
        asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
}

bool ClientDiscovery::do_client_discovery(AppIdSession& asd, Packet* p,
    AppidSessionDirection direction, AppidChangeBits& change_bits)
{
    bool is_discovery_done = false;
    AppInfoTableEntry* entry;
    bool was_service = asd.is_service_detected();
    AppId tp_app_id = asd.get_tp_app_id();

    if (asd.client_disco_state == APPID_DISCO_STATE_NONE and
        p->dsize and direction == APP_ID_FROM_INITIATOR)
    {
        if ( p->flow->get_session_flags() & SSNFLAG_MIDSTREAM )
            asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
        else if ( asd.get_session_flags(APPID_SESSION_HTTP_SESSION) )
            asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
        else
        {
            get_detector_candidates_list(asd, p, direction);
            is_discovery_done = true;
            asd.client_disco_state = APPID_DISCO_STATE_STATEFUL;
        }
    }

    if (asd.is_encrypted_oportunistic_tls_session() and asd.encrypted.client_id > 0)
    {
        asd.set_client_id(asd.encrypted.client_id);
        asd.set_client_detected();
        asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
    }

    if (asd.client_disco_state == APPID_DISCO_STATE_STATEFUL)
    {
        if (asd.client_candidates.empty() and tp_app_id > APP_ID_NONE and
            asd.is_tp_appid_available())
        {
            // Third party has positively identified appId and we don't have a candidate
            entry = asd.get_odp_ctxt().get_app_info_mgr().get_app_info_entry(tp_app_id);
            if ( entry and entry->client_detector and
                ( ( entry->flags & ( APPINFO_FLAG_CLIENT_ADDITIONAL | APPINFO_FLAG_CLIENT_USER ) ) and
                    asd.get_session_flags(APPID_SESSION_DISCOVER_USER) ) )
            {
                // Dig deeper only if our detector identifies additional information
                asd.client_detector = entry->client_detector;
            }
            else
            {
                asd.set_client_detected();
                asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
            }
        }
        else if (asd.client_candidates.empty())
        {
            asd.set_client_detected();
            asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
        }
    }

    if (asd.client_disco_state == APPID_DISCO_STATE_STATEFUL)
    {
        if ( direction == APP_ID_FROM_INITIATOR )
        {
            /* get out if we've already tried to validate a client app */
            if (!asd.is_client_detected() )
                exec_client_detectors(asd, p, direction, change_bits);
        }
        else if ( asd.service_disco_state != APPID_DISCO_STATE_STATEFUL
            && asd.get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS) )
        {
            exec_client_detectors(asd, p, direction, change_bits);
        }
    }

    if ( !was_service && asd.is_service_detected() )
        asd.sync_with_snort_protocol_id(asd.get_service_id(), p);

    return is_discovery_done;
}
