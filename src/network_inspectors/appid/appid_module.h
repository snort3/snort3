//--------------------------------------------------------------------------
// Copyright (C) 2016-2017 Cisco and/or its affiliates. All rights reserved.
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

// appid_module.h author davis mcpherson <davmcphe@cisco.com>
// Created on: May 10, 2016

#ifndef APPID_MODULE_H
#define APPID_MODULE_H

#include "framework/module.h"
#include "appid_config.h"

extern THREAD_LOCAL ProfileStats appidPerfStats;

#define MOD_NAME "appid"
#define MOD_HELP "application and service identification"

struct AppIdStats
{
    PegCount packets;
    PegCount processed_packets;
    PegCount ignored_packets;
    PegCount aim_clients;
    PegCount battlefield_flows;
    PegCount bgp_flows;
    PegCount bit_clients;
    PegCount bit_flows;
    PegCount bittracker_clients;
    PegCount bootp_flows;
    PegCount dcerpc_tcp_flows;
    PegCount dcerpc_udp_flows;
    PegCount direct_connect_flows;
    PegCount dns_tcp_flows;
    PegCount dns_udp_flows;
    PegCount ftp_flows;
    PegCount ftps_flows;
    PegCount http_flows;
    PegCount imap_flows;
    PegCount imaps_flows;
    PegCount irc_flows;
    PegCount kerberos_clients;
    PegCount kerberos_flows;
    PegCount kerberos_users;
    PegCount lpr_flows;
    PegCount mdns_flows;
    PegCount msn_clients;
    PegCount mysql_flows;
    PegCount netbios_dgm_flows;
    PegCount netbios_ns_flows;
    PegCount netbios_ssn_flows;
    PegCount nntp_flows;
    PegCount ntp_flows;
    PegCount pop_flows;
    PegCount pop3_clients;
    PegCount pop3s_clients;
    PegCount radius_flows;
    PegCount rexec_flows;
    PegCount rfb_flows;
    PegCount rlogin_flows;
    PegCount rpc_flows;
    PegCount rshell_flows;
    PegCount rsync_flows;
    PegCount rtmp_flows;
    PegCount rtp_clients;
    PegCount sip_clients;
    PegCount sip_flows;
    PegCount smtp_aol_clients;
    PegCount smtp_applemail_clients;
    PegCount smtp_eudora_clients;
    PegCount smtp_eudora_pro_clients;
    PegCount smtp_evolution_clients;
    PegCount smtp_kmail_clients;
    PegCount smtp_lotus_notes_clients;
    PegCount smtp_microsoft_outlook_clients;
    PegCount smtp_microsoft_outlook_express_clients;
    PegCount smtp_microsoft_outlook_imo_clients;
    PegCount smtp_mutt_clients;
    PegCount smtp_thunderbird_clients;
    PegCount smtp_flows;
    PegCount smtps_flows;
    PegCount snmp_flows;
    PegCount ssh_clients;
    PegCount ssh_flows;
    PegCount ssl_flows;
    PegCount telnet_flows;
    PegCount tftp_flows;
    PegCount timbuktu_clients;
    PegCount timbuktu_flows;
    PegCount tns_clients;
    PegCount tns_flows;
    PegCount vnc_clients;
    PegCount yahoo_messenger_clients;
};

extern THREAD_LOCAL AppIdStats appid_stats;

class AppIdModule : public Module
{
public:
    AppIdModule();
    ~AppIdModule();

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    const AppIdModuleConfig* get_data();

private:
    AppIdModuleConfig* config;
};

#endif

