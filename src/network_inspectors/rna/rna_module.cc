//--------------------------------------------------------------------------
// Copyright (C) 2019-2022 Cisco and/or its affiliates. All rights reserved.
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

// rna_module.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_module.h"

#include <cassert>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>

#include "control/control.h"
#include "host_tracker/host_cache.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "utils/util.h"

#include "data_purge_cmd.h"
#include "rna_fingerprint_smb.h"
#include "rna_fingerprint_tcp.h"
#include "rna_fingerprint_ua.h"
#include "rna_fingerprint_udp.h"
#include "rna_mac_cache.h"
#include "rna_pnd.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;
using namespace std;

#define MAC_STRLEN 17

THREAD_LOCAL const Trace* rna_trace = nullptr;

//-------------------------------------------------------------------------
// rna commands, params, and pegs
//-------------------------------------------------------------------------
static int dump_mac_cache(lua_State* L)
{
    RnaModule* mod = (RnaModule*) ModuleManager::get_module(RNA_NAME);
    Inspector* rna = InspectorManager::get_inspector(RNA_NAME, true);
    if ( rna && mod )
        mod->log_mac_cache( luaL_optstring(L, 1, nullptr) );
    return 0;
}

static inline string format_dump_mac(const uint8_t mac[MAC_SIZE])
{
    stringstream ss;
    ss << hex;

    for(int i=0; i < MAC_SIZE; i++)
    {
        ss << setfill('0') << setw(2) << static_cast<int>(mac[i]);
        if (i != MAC_SIZE - 1)
            ss << ":";
    }

    return ss.str();
}

static int purge_data(lua_State* L)
{
    Inspector* rna = InspectorManager::get_inspector(RNA_NAME, true);
    if ( rna )
    {
        HostCacheMac* mac_cache = new HostCacheMac(MAC_CACHE_INITIAL_SIZE);
        ControlConn* ctrlcon = ControlConn::query_from_lua(L);
        main_broadcast_command(new DataPurgeAC(mac_cache), ctrlcon);

        host_cache.invalidate();

        ctrlcon->respond("data purge done\n");
        LogMessage("data purge done\n");
    }

    return 0;
}

bool FpProcReloadTuner::tinit()
{
    set_tcp_fp_processor(mod_conf.tcp_processor);
    set_ua_fp_processor(mod_conf.ua_processor);
    set_udp_fp_processor(mod_conf.udp_processor);
    set_smb_fp_processor(mod_conf.smb_processor);
    return false;  // no work to do after this
}

static bool get_mac_from_args(lua_State* L, uint8_t* mac_addr)
{
    const char* lua_in = luaL_optstring(L, 1, nullptr);

    size_t input_len = strlen(lua_in);
    if ( input_len != MAC_STRLEN)
    {
        LogMessage("Improperly formatted MAC address, use format aa:bb:cc:dd:ee:ff\n");
        return false;
    }

    string in(lua_in);
    istringstream tokinizer(in);
    stringstream hex_parser;
    string tok;
    int idx = 0;

    // Need to use uint16_t, otherwise stringstream sees uint_8 (char*)
    // and converts the string to a char* (not what was intended)
    uint16_t tmp_byte = 0;

    while (getline(tokinizer, tok, ':'))
    {
        hex_parser << hex << tok;
        hex_parser >> tmp_byte;
        mac_addr[idx++] = (uint8_t) tmp_byte;

        if ( hex_parser.fail() or tok.size() != 2 )
        {
            LogMessage("Improperly formatted MAC address, use format "
             "aa:bb:cc:dd:ee:ff\n");
            return false;
        }

        hex_parser.str(string());
        hex_parser.clear();
    }

    if ( idx != MAC_SIZE )
    {
        LogMessage("Improperly formatted MAC address, use format aa:bb:cc:dd:ee:ff\n");
        return false;
    }

    return true;

}

static int delete_mac_host(lua_State* L)
{
    Inspector* rna = InspectorManager::get_inspector(RNA_NAME, true);
    if ( rna )
    {
        uint8_t mac[MAC_SIZE] = {0};

        const char* lua_in = luaL_optstring(L, 1, nullptr);

        if ( lua_in == nullptr )
        {
            LogMessage("Usage: rna.delete_mac_host(mac)\n");
            return 0;
        }

        bool valid_mac = get_mac_from_args(L, mac);
        if (!valid_mac)
            return 0;

        MacKey search_mk(mac);
        HostCacheMac* mac_cache = get_host_cache_mac();
        assert(mac_cache);

        bool success = mac_cache->remove((const uint8_t*) &search_mk);

        if (!success)
        {
            LogMessage("MAC not found in cache\n");
            return 0;
        }

        LogMessage("rna.delete_mac_host completed successfully\n");
    }
    return 0;
}

static int delete_mac_host_proto(lua_State* L)
{
    Inspector* rna = InspectorManager::get_inspector(RNA_NAME, true);
    if ( rna )
    {
        uint8_t mac[MAC_SIZE] = {0};

        const char* lua_in = luaL_optstring(L, 1, nullptr);

        if ( lua_in == nullptr )
        {
            LogMessage("Usage: rna.delete_mac_host_proto(mac, proto)\n");
            return 0;
        }

        bool valid_mac = get_mac_from_args(L, mac);
        if (!valid_mac)
            return 0;

        MacKey search_mk(mac);
        HostCacheMac* mac_cache = get_host_cache_mac();
        assert(mac_cache);

        auto htm = mac_cache->find((const uint8_t*) &search_mk);

        if (!htm)
        {
            LogMessage("MAC not found in cache\n");
            return 0;
        }

        uint16_t proto = luaL_optnumber(L, 2, 0);
        bool success = false;
        if (proto != 0)
            success = htm->delete_proto(proto);

        if (success)
            LogMessage("rna.delete_mac_host_proto completed successfully\n");
        else
            LogMessage("rna.delete_mac_host_proto failed to delete protocol\n");

    }
    return 0;
}


static const Parameter mac_delete_params[] =
{
    { "mac", Parameter::PT_STRING, nullptr, nullptr, "MAC address to delete, "
        "format aa:bb:cc:dd:ee:ff"},
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter mac_delete_proto_params[] =
{
    { "mac", Parameter::PT_STRING, nullptr, nullptr, "MAC address with associated protocol, "
        "format: aa:bb:cc:dd:ee:ff"},
    { "proto", Parameter::PT_INT, nullptr, nullptr, "protocol to delete from MAC host, "
        "format: Ethertype, in decimal" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command rna_cmds[] =
{
    { "dump_macs", dump_mac_cache, nullptr, "dump rna's internal MAC trackers" },
    { "delete_mac_host", delete_mac_host, mac_delete_params,
        "delete a MAC from rna's MAC cache"},
    { "delete_mac_host_proto", delete_mac_host_proto, mac_delete_proto_params,
        "delete a protocol associated with a MAC host"},
    { "purge_data", purge_data, nullptr,
        "purge all host cache and mac cache data"},
    { nullptr, nullptr, nullptr, nullptr }
};

static const Parameter user_agent_parts[] =
{
    { "substring", Parameter::PT_STRING, nullptr, nullptr, "a substring of user agent string" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter rna_fp_params[] =
{
    { "fpid", Parameter::PT_INT, "0:max32", "0",
      "fingerprint id" },

    { "type", Parameter::PT_INT, "0:max32", "0",
      "fingerprint type" },

    { "uuid", Parameter::PT_STRING, nullptr, nullptr,
      "fingerprint uuid" },

    { "ttl", Parameter::PT_INT, "0:255", "0",
      "fingerprint ttl" },

    { "tcp_window", Parameter::PT_STRING, nullptr, nullptr,
      "fingerprint tcp window" },

    { "mss", Parameter::PT_STRING, nullptr, "X",
      "fingerprint mss" },

    { "id", Parameter::PT_STRING, nullptr, "X",
      "id" },

    { "topts", Parameter::PT_STRING, nullptr, nullptr,
      "fingerprint tcp options" },

    { "ws", Parameter::PT_STRING, nullptr, "X",
      "fingerprint window size" },

    { "df", Parameter::PT_BOOL, nullptr, "false",
      "fingerprint don't fragment flag" },

    { "ua_type", Parameter::PT_ENUM, "os | device | jail-broken | jail-broken-host",
      "os", "type of user agent fingerprints" },

    { "user_agent", Parameter::PT_LIST, user_agent_parts, nullptr,
      "list of user agent information parts to match" },

    { "host_name", Parameter::PT_STRING, nullptr, nullptr,
      "host name information" },

    { "device", Parameter::PT_STRING, nullptr, nullptr,
      "device information" },

    { "dhcp55", Parameter::PT_STRING, nullptr, nullptr,
      "dhcp option 55 values" },

    { "dhcp60", Parameter::PT_STRING, nullptr, nullptr,
      "dhcp option 60 values" },

    { "major", Parameter::PT_INT, "0:max31", nullptr,
      "smb major version" },

    { "minor", Parameter::PT_INT, "0:max31", nullptr,
      "smb minor version" },

    { "flags", Parameter::PT_INT, "0:max32", nullptr,
      "smb flags" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter rna_params[] =
{
    { "rna_conf_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to rna configuration" },

    { "enable_logger", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable writing discovery events into logger" },

    { "log_when_idle", Parameter::PT_BOOL, nullptr, "false",
      "enable host update logging when snort is idle" },

    { "dump_file", Parameter::PT_STRING, nullptr, nullptr,
      "file name to dump RNA mac cache on shutdown; won't dump by default" },

    { "tcp_fingerprints", Parameter::PT_LIST, rna_fp_params, nullptr,
      "list of tcp fingerprints" },

    { "ua_fingerprints", Parameter::PT_LIST, rna_fp_params, nullptr,
      "list of user agent fingerprints" },

    { "udp_fingerprints", Parameter::PT_LIST, rna_fp_params, nullptr,
      "list of udp fingerprints" },

    { "smb_fingerprints", Parameter::PT_LIST, rna_fp_params, nullptr,
      "list of smb fingerprints" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo rna_pegs[] =
{
    { CountType::SUM, "appid_change", "count of appid change events received" },
    { CountType::SUM, "cpe_os", "count of CPE OS events received" },
    { CountType::SUM, "icmp_bidirectional", "count of bidirectional ICMP flows received" },
    { CountType::SUM, "icmp_new", "count of new ICMP flows received" },
    { CountType::SUM, "ip_bidirectional", "count of bidirectional IP received" },
    { CountType::SUM, "ip_new", "count of new IP flows received" },
    { CountType::SUM, "udp_bidirectional", "count of bidirectional UDP flows received" },
    { CountType::SUM, "udp_new", "count of new UDP flows received" },
    { CountType::SUM, "tcp_syn", "count of TCP SYN packets received" },
    { CountType::SUM, "tcp_syn_ack", "count of TCP SYN-ACK packets received" },
    { CountType::SUM, "tcp_midstream", "count of TCP midstream packets received" },
    { CountType::SUM, "other_packets", "count of packets received without session tracking" },
    { CountType::SUM, "change_host_update", "count number of change host update events" },
    { CountType::SUM, "dhcp_data", "count of DHCP data events received" },
    { CountType::SUM, "dhcp_info", "count of new DHCP lease events received" },
    { CountType::SUM, "smb", "count of new SMB events received" },
    { CountType::SUM, "netflow_record", "count of netflow record events received" },
    { CountType::END, nullptr, nullptr},
};

//-------------------------------------------------------------------------
// rna module
//-------------------------------------------------------------------------

RnaModule::RnaModule() : Module(RNA_NAME, RNA_HELP, rna_params)
{ }

RnaModule::~RnaModule()
{
    if ( dump_file )
    {
        log_mac_cache(dump_file);
        snort_free((void*)dump_file);
    }

    delete mod_conf;
}

bool RnaModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!is_valid_fqn(fqn))
        return false;

    if (!mod_conf)
        mod_conf = new RnaModuleConfig;

    if (!strcmp(fqn, "rna.tcp_fingerprints"))
    {
        fingerprint.clear();
        if (!mod_conf->tcp_processor)
            mod_conf->tcp_processor = new TcpFpProcessor;
    }
    else if (!strcmp(fqn, "rna.ua_fingerprints"))
    {
        fingerprint.clear();
        if (!mod_conf->ua_processor)
            mod_conf->ua_processor = new UaFpProcessor;
    }
    else if (!strcmp(fqn, "rna.udp_fingerprints"))
    {
        fingerprint.clear();
        if (!mod_conf->udp_processor)
            mod_conf->udp_processor = new UdpFpProcessor;
    }
    else if (!strcmp(fqn, "rna.smb_fingerprints"))
    {
        fingerprint.clear();
        if (!mod_conf->smb_processor)
            mod_conf->smb_processor = new SmbFpProcessor;
    }

    return true;
}

bool RnaModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if (v.is("rna_conf_path"))
        mod_conf->rna_conf_path = string(v.get_string());
    else if (v.is("enable_logger"))
        mod_conf->enable_logger = v.get_bool();
    else if (v.is("log_when_idle"))
        mod_conf->log_when_idle = v.get_bool();
    else if ( v.is("dump_file") )
    {
        if ( dump_file )
            snort_free((void*)dump_file);
        dump_file = snort_strdup(v.get_string());
    }
    else if ( fqn and ( strstr(fqn, "rna.tcp_fingerprints") or
        strstr(fqn, "rna.ua_fingerprints") or strstr(fqn, "rna.udp_fingerprints")
        or strstr(fqn, "rna.smb_fingerprints") ) )
    {
        if (v.is("fpid"))
            fingerprint.fpid = v.get_uint32();
        else if (v.is("type"))
            fingerprint.fp_type = v.get_uint32();
        else if (v.is("uuid"))
            fingerprint.fpuuid = v.get_string();
        else if (v.is("ttl"))
            fingerprint.ttl = v.get_uint8();
        else if (v.is("tcp_window"))
            fingerprint.tcp_window = v.get_string();
        else if (v.is("mss"))
            fingerprint.mss = v.get_string();
        else if (v.is("id"))
            fingerprint.id = v.get_string();
        else if (v.is("topts"))
            fingerprint.topts = v.get_string();
        else if (v.is("ws"))
            fingerprint.ws = v.get_string();
        else if (v.is("df"))
            fingerprint.df = v.get_bool();
        else if (v.is("ua_type"))
            fingerprint.ua_type = (UserAgentInfoType)v.get_uint8();
        else if (v.is("host_name"))
            fingerprint.host_name = v.get_string();
        else if (v.is("device"))
            fingerprint.device = v.get_string();
        else if (v.is("user_agent"))
            return true;
        else if (v.is("substring"))
        {
            const auto& ua_part = v.get_string();
            if ( !ua_part )
                return false;
            fingerprint.user_agent.emplace_back(ua_part);
        }
        else if (v.is("dhcp55"))
            fingerprint.dhcp55 = v.get_string();
        else if (v.is("dhcp60"))
            fingerprint.dhcp60 = v.get_string();
        else if (v.is("major"))
            fingerprint.smb_major = v.get_uint32();
        else if (v.is("minor"))
            fingerprint.smb_minor = v.get_uint32();
        else if (v.is("flags"))
            fingerprint.smb_flags = v.get_uint32();
        else
            return false;
    }
    return true;
}

bool RnaModule::end(const char* fqn, int index, SnortConfig* sc)
{
    if ( mod_conf == nullptr || !is_valid_fqn(fqn) )
        return false;

    if ( !strcmp(fqn, RNA_NAME) )
    {
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN); // Internal flag to track TCP on SYN

        if ( sc->ip_frags_only() )
        {
            WarningMessage("RNA: Disabling stream.ip_frags_only option!\n");
            sc->clear_run_flags(RUN_FLAG__IP_FRAGS_ONLY);
        }

        if ( mod_conf->tcp_processor )
        {
            mod_conf->tcp_processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::SERVER);
            mod_conf->tcp_processor->make_tcp_fp_tables(TcpFpProcessor::TCP_FP_MODE::CLIENT);
        }
    }

    if ( index > 0 and mod_conf->tcp_processor and !strcmp(fqn, "rna.tcp_fingerprints") )
    {
        // there is an implicit conversion here from raw fingerprint (all
        // strings) to tcp fingerprint, done by the tcp fingerprint constructor
        mod_conf->tcp_processor->push(fingerprint);
        fingerprint.clear();
    }
    else if ( index > 0 and mod_conf->ua_processor and !strcmp(fqn, "rna.ua_fingerprints") )
    {
        mod_conf->ua_processor->push(fingerprint);
        fingerprint.clear();
    }
    else if ( index > 0 and mod_conf->udp_processor and !strcmp(fqn, "rna.udp_fingerprints") )
    {
        mod_conf->udp_processor->push(fingerprint);
        fingerprint.clear();
    }
    else if ( index > 0 and mod_conf->smb_processor and !strcmp(fqn, "rna.smb_fingerprints") )
    {
        mod_conf->smb_processor->push(fingerprint);
        fingerprint.clear();
    }

    return true;
}

const Command* RnaModule::get_commands() const
{
    return rna_cmds;
}

RnaModuleConfig* RnaModule::get_config()
{
    RnaModuleConfig* tmp = mod_conf;
    mod_conf = nullptr;
    return tmp;
}

PegCount* RnaModule::get_counts() const
{ return (PegCount*)&rna_stats; }

const PegInfo* RnaModule::get_pegs() const
{ return rna_pegs; }

ProfileStats* RnaModule::get_profile() const
{ return &rna_perf_stats; }

void RnaModule::set_trace(const Trace* trace) const
{ rna_trace = trace; }

const TraceOption* RnaModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    static const TraceOption rna_trace_options(nullptr, 0, nullptr);
    return &rna_trace_options;
#endif
}

bool RnaModule::log_mac_cache(const char* outfile)
{
    if ( !outfile )
    {
        LogMessage("File name is needed!\n");
        return false;
    }

    struct stat file_stat;
    if ( stat(outfile, &file_stat) == 0 )
    {
        LogMessage("File %s already exists!\n", outfile);
        return false;
    }

    ofstream out_stream(outfile);
    if ( !out_stream )
    {
        snort::LogMessage("Error opening %s for dumping MAC cache", outfile);
    }

    string str;
    HostCacheMac* host_cache_mac = get_host_cache_mac();
    assert(host_cache_mac);
    const auto&& lru_data = host_cache_mac->get_all_data();
    out_stream << "Current mac cache size: " << host_cache_mac->mem_size() << " bytes, "
        << lru_data.size() << " trackers" << endl << endl;
    for ( const auto& elem : lru_data )
    {
        str = "MAC: ";
        str += format_dump_mac(elem.first.mac_addr);
        str += "\n Key: " + to_string(hash_mac(elem.first.mac_addr));
        elem.second->stringify(str);
        out_stream << str << endl << endl;
    }
    out_stream.close();

    return false;
}

bool RnaModule::is_valid_fqn(const char* fqn) const
{
    return !strcmp(fqn, RNA_NAME) or !strcmp(fqn, "rna.tcp_fingerprints") or
        !strcmp(fqn, "rna.ua_fingerprints") or !strcmp(fqn, "rna.ua_fingerprints.user_agent") or
        !strcmp(fqn, "rna.udp_fingerprints") or !strcmp(fqn, "rna.smb_fingerprints");
}


#ifdef UNIT_TEST

TEST_CASE("RNA module", "[rna_module]")
{
    SECTION("module begin, set, end")
    {
        RnaModule mod;
        SnortConfig sc;

        CHECK_FALSE(mod.begin("dummy", 0, nullptr));
        CHECK(mod.end("rna", 0, nullptr) == false);
        CHECK(mod.begin("rna", 0, nullptr) == true);

        Value v1("rna.conf");
        v1.set(Parameter::find(rna_params, "rna_conf_path"));
        CHECK(mod.set(nullptr, v1, nullptr) == true);
        CHECK(mod.end("rna", 0, &sc) == true);

        RnaModuleConfig* rc = mod.get_config();
        CHECK(rc != nullptr);
        CHECK(rc->rna_conf_path == "rna.conf");

        delete rc;
    }

    SECTION("ip_frags_only is false")
    {
        RnaModule mod;
        SnortConfig sc;

        sc.set_run_flags(RUN_FLAG__IP_FRAGS_ONLY);
        CHECK(sc.ip_frags_only() == true);

        CHECK(mod.begin(RNA_NAME, 0, nullptr) == true);
        CHECK(mod.end(RNA_NAME, 0, &sc) == true);
        CHECK(sc.ip_frags_only() == false);

        delete mod.get_config();
    }

    SECTION("track_on_syn is true")
    {
        RnaModule mod;
        SnortConfig sc;

        sc.clear_run_flags(RUN_FLAG__TRACK_ON_SYN);
        CHECK(sc.track_on_syn() == false);

        CHECK(mod.begin(RNA_NAME, 0, nullptr) == true);
        CHECK(mod.end(RNA_NAME, 0, &sc) == true);
        CHECK(sc.track_on_syn() == true);

        delete mod.get_config();
    }
}

#endif
