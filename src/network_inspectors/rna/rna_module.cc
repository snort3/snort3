//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "log/messages.h"
#include "main/snort_config.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

//-------------------------------------------------------------------------
// rna params and pegs
//-------------------------------------------------------------------------

static const Parameter rna_params[] =
{
    { "rna_conf_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to RNA configuration" },

    { "rna_util_lib_path", Parameter::PT_STRING, nullptr, nullptr,
      "path to library for utilities such as fingerprint decoder" },

    { "fingerprint_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to fingerprint patterns" },

    { "custom_fingerprint_dir", Parameter::PT_STRING, nullptr, nullptr,
      "directory to custom fingerprint patterns" },

    { "enable_logger", Parameter::PT_BOOL, nullptr, "true",
      "enable or disable writing discovery events into logger" },

    { "log_when_idle", Parameter::PT_BOOL, nullptr, "false",
      "enable host update logging when snort is idle" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const PegInfo rna_pegs[] =
{
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
    { CountType::END, nullptr, nullptr},
};

//-------------------------------------------------------------------------
// rna module
//-------------------------------------------------------------------------

RnaModule::RnaModule() : Module(RNA_NAME, RNA_HELP, rna_params)
{ }

RnaModule::~RnaModule()
{
    delete mod_conf;
}

bool RnaModule::begin(const char* fqn, int, SnortConfig*)
{
    if (strcmp(fqn, RNA_NAME))
        return false;
    else if (!mod_conf)
        mod_conf = new RnaModuleConfig;
    return true;
}

bool RnaModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("rna_conf_path"))
        mod_conf->rna_conf_path = std::string(v.get_string());
    else if (v.is("rna_util_lib_path"))
        mod_conf->rna_util_lib_path = std::string(v.get_string());
    else if (v.is("fingerprint_dir"))
        mod_conf->fingerprint_dir = std::string(v.get_string());
    else if (v.is("custom_fingerprint_dir"))
        mod_conf->custom_fingerprint_dir = std::string(v.get_string());
    else if (v.is("enable_logger"))
        mod_conf->enable_logger = v.get_bool();
    else if (v.is("log_when_idle"))
        mod_conf->log_when_idle = v.get_bool();
    else
        return false;

    return true;
}

bool RnaModule::end(const char* fqn, int, SnortConfig* sc)
{
    if ( mod_conf == nullptr and strcmp(fqn, RNA_NAME) == 0 )
        return false;

    sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN); // Internal flag to track TCP on SYN

    if ( sc->ip_frags_only() )
    {
        WarningMessage("RNA: Disabling stream.ip_frags_only option!\n");
        sc->clear_run_flags(RUN_FLAG__IP_FRAGS_ONLY);
    }

    return true;
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

        Value v2("rna_util.so");
        v2.set(Parameter::find(rna_params, "rna_util_lib_path"));
        CHECK(mod.set(nullptr, v2, nullptr) == true);

        Value v3("/dir/fingerprints");
        v3.set(Parameter::find(rna_params, "fingerprint_dir"));
        CHECK(mod.set(nullptr, v3, nullptr) == true);

        Value v4("/dir/custom_fingerprints");
        v4.set(Parameter::find(rna_params, "custom_fingerprint_dir"));
        CHECK(mod.set(nullptr, v4, nullptr) == true);

        Value v5("dummy");
        CHECK(mod.set(nullptr, v5, nullptr) == false);
        CHECK(mod.end("rna", 0, &sc) == true);

        RnaModuleConfig* rc = mod.get_config();
        CHECK(rc != nullptr);
        CHECK(rc->rna_conf_path == "rna.conf");
        CHECK(rc->rna_util_lib_path == "rna_util.so");
        CHECK(rc->fingerprint_dir == "/dir/fingerprints");
        CHECK(rc->custom_fingerprint_dir == "/dir/custom_fingerprints");

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
