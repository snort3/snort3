//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// appid_ssh_event_handler.cc author Daniel McGarvey <danmcgar@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_ssh_event_handler.h"

#include "detector_plugins/ssh_patterns.h"
#include "service_inspectors/ssh/ssh.h"
#include "appid_debug.h"
#include "appid_detector.h"
#include "appid_inspector.h"

using namespace snort;
using namespace std;

static bool handle_protocol(SshEvent& event, SshAppIdInfo* fd)
{
    // FIXIT-L
    // There isn't any real specification on what separates the vendor name from version number. It
    // seems to usually be an underscore or dash, but there are some clients where this pattern
    // isn't followed. For example, in the Bitvise SSH client, the version string has the version
    // number first, separated by a space from the subsequent client identification. Parsing may
    // need to be enhanced to handle unusual version strings for new client apps.
    const string& protocol = event.get_version_str();

    const char* vendor_begin = strchr(protocol.c_str() + sizeof(SSH_BANNER) - 1, '-');
    if (vendor_begin != nullptr)
        vendor_begin++;
    else
        return false;

    const char* vendor_end = strpbrk(vendor_begin, "_- \r\n");
    if (vendor_end == nullptr)
        return false;

    size_t vendor_len = (size_t)(vendor_end - vendor_begin);
    fd->vendor.assign(vendor_begin, vendor_len);

    const char* version_begin = vendor_end + 1;
    const char* version_end  = strpbrk(version_begin, " \r\n");
    if (version_end == nullptr)
        return false;
    size_t version_len = (size_t)(version_end - version_begin);
    fd->version.assign(version_begin, version_len);

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "SSH event handler read SSH version string with vendor %s and version %s\n",
        fd->vendor.c_str(), fd->version.c_str());

    return true;
}


static void handle_failure(AppIdSession& asd, SshEventFlowData& data)
{
    asd.set_service_id(APP_ID_UNKNOWN, asd.get_odp_ctxt());
    asd.set_service_detected();

    asd.set_client_id(APP_ID_UNKNOWN);
    asd.set_client_detected();

    data.failed = true;
}

static void client_success(const SshAppIdInfo& fd, AppIdSession& asd, AppidChangeBits& change_bits)
{
    const SshPatternMatchers& table = asd.get_odp_ctxt().get_ssh_matchers();
    AppId client_id;

    if (table.has_pattern(fd.vendor))
    {
        client_id = table.get_appid(fd.vendor);
        appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "SSH event handler identified client with AppId %u\n", client_id);
    }
    else
    {
        client_id = APP_ID_SSH;
        appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "SSH event handler client detected, but vendor not recognized\n");
    }

    asd.set_client_id(client_id);
    asd.set_ss_application_ids(client_id, APP_ID_NONE, change_bits);
    asd.set_client_version(fd.version.c_str(), change_bits);
    asd.set_client_detected();
    asd.client_inferred_service_id = APP_ID_SSH;
}

static void service_success(SshAppIdInfo& fd, const Packet& p, AppIdSession& asd,
    AppidChangeBits& change_bits)
{
    int16_t group;
    uint16_t port;
    const SfIp* ip;

    if (p.is_from_client())
    {
        ip = p.ptrs.ip_api.get_dst();
        port = p.ptrs.dp;
        group = p.get_egress_group();
    }
    else
    {
        ip = p.ptrs.ip_api.get_src();
        port = p.ptrs.sp;
        group = p.get_ingress_group();
    }

    asd.set_server_info(*ip, port, group);
    asd.set_service_id(APP_ID_SSH, asd.get_odp_ctxt());
    asd.set_application_ids_service(APP_ID_SSH, change_bits);
    asd.set_service_vendor(fd.vendor.c_str(), change_bits);
    asd.set_service_version(fd.version.c_str(), change_bits);
    asd.set_service_detected();
}

static void handle_success(SshEventFlowData& data, const SshEvent& event,
    AppIdSession& asd, AppidChangeBits& change_bits)
{
    service_success(data.service_info, *event.get_packet(), asd, change_bits);
    client_success(data.client_info, asd, change_bits);

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "SSH event handler service detected\n");
}


static void free_ssh_flow_data(void* data)
{
    delete (SshEventFlowData* )data;
}

unsigned int SshEventHandler::id;

void SshEventHandler::handle(DataEvent& event, Flow* flow)
{
    if (!flow)
        return;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!asd)
        return;

    if (asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version())
        return; // Skip detection for sessions using old odp context after odp reload
    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    SshEventFlowData* data = (SshEventFlowData* )asd->get_flow_data(id);
    Packet* p = DetectionEngine::get_current_packet();

    if (data and data->failed)
    {
        appid_log(p, TRACE_DEBUG_LEVEL, "SSH detection failed, ignoring event\n");
        return;
    }

    if (!data)
    {
        data = new SshEventFlowData;
        asd->add_flow_data(data, id, &free_ssh_flow_data);
    }

    SshEvent& ssh_event = (SshEvent&)event;
    SshAppIdInfo* fd;
    if (ssh_event.get_direction() == PKT_FROM_SERVER)
        fd = &data->service_info;
    else
        fd = &data->client_info;

    if (fd->finished)
        return;

    AppidChangeBits change_bits;

    switch(ssh_event.get_event_type())
    {
    case SSH_VERSION_STRING:
        if (handle_protocol(ssh_event, fd))
        {
            if (asd->get_session_flags(APPID_SESSION_EARLY_SSH_DETECTED))
            {
                appid_log(p, TRACE_DEBUG_LEVEL, "Early detection of SSH\n");
                handle_success(*data, ssh_event, *asd, change_bits);
                asd->publish_appid_event(change_bits, *ssh_event.get_packet());
                asd->clear_session_flags(APPID_SESSION_EARLY_SSH_DETECTED);
            }
        }
        else
            appid_log(p, TRACE_DEBUG_LEVEL, "SSH event handler received unsupported protocol %s\n",
                ssh_event.get_version_str().c_str());

        break;

    case SSH_VALIDATION:
        switch (ssh_event.get_validation_result())
        {
        case SSH_VALID_KEXINIT:
                appid_log(p, TRACE_DEBUG_LEVEL, "SSH event handler received valid key exchange\n");
            fd->finished = true;
            break;

        case SSH_INVALID_KEXINIT:
                appid_log(p, TRACE_DEBUG_LEVEL, "SSH event handler received invalid key exchange\n");
            handle_failure(*asd, *data);
            break;

        case SSH_INVALID_VERSION:
                appid_log(p, TRACE_DEBUG_LEVEL, "SSH event handler received invalid version\n");
            handle_failure(*asd, *data);
            break;

        default:
            break;
        }

        if (data->service_info.finished and data->client_info.finished)
        {
            handle_success(*data, ssh_event, *asd, change_bits);
            asd->publish_appid_event(change_bits, *ssh_event.get_packet());
        }
        // Don't generate an event in case of failure. We want to give third-party a chance

        break;
    }
}
