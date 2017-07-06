//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
// data_log.cc author Russ Combs <rcombs@sourcefire.com>

#include "flow/flow.h"
#include "framework/data_bus.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "log/text_log.h"

static const char* s_name = "data_log";
static const char* f_name = "data.log";
static const char* s_help = "log selected published data to data.log";

static THREAD_LOCAL SimpleStats dl_stats;

//-------------------------------------------------------------------------
// log stuff
//-------------------------------------------------------------------------

static THREAD_LOCAL TextLog* tlog = nullptr;

static void dl_tinit()
{
    tlog = TextLog_Init(f_name, 64*K_BYTES, 1*M_BYTES);
}

static void dl_tterm()
{
    TextLog_Term(tlog);
}

//-------------------------------------------------------------------------
// data stuff
//-------------------------------------------------------------------------

class LogHandler : public DataHandler
{
public:
    LogHandler(const std::string& s)
    { key = s; }

    void handle(DataEvent& e, Flow*);

private:
    std::string key;
};

void LogHandler::handle(DataEvent& e, Flow* f)
{
    unsigned n;
    const char* b = (char*)e.get_data(n);

    // FIXIT-L hexify binary data
    std::string val(b, n);

    TextLog_Print(tlog, "%u, ", time(nullptr));
    TextLog_Print(tlog, "%s, %d, ", f->client_ip.ntoa(), f->client_port);
    TextLog_Print(tlog, "%s, %d, ", f->server_ip.ntoa(), f->server_port);
    TextLog_Print(tlog, "%s, %*s\n", key.c_str(), n, val.c_str());

    dl_stats.total_packets++;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class DataLog : public Inspector
{
public:
    DataLog(const std::string& s) { key = s; }

    void show(SnortConfig*) override;
    void eval(Packet*) override { }

    bool configure(SnortConfig*) override
    {
        get_data_bus().subscribe(key.c_str(), new LogHandler(key));
        return true;
    }

private:
    std::string key;
};

void DataLog::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    key = %s\n", key.c_str());
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter dl_params[] =
{
    { "key", Parameter::PT_SELECT, "http_uri | http_raw_uri", "http_raw_uri",
      "name of data buffer to log" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class DataLogModule : public Module
{
public:
    DataLogModule() : Module(s_name, s_help, dl_params)
    { }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&dl_stats; }

    bool set(const char*, Value& v, SnortConfig*) override;

public:
    std::string key;
};

bool DataLogModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("key") )
        key = v.get_string();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DataLogModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* dl_ctor(Module* m)
{
    DataLogModule* mod = (DataLogModule*)m;
    return new DataLog(mod->key);
}

static void dl_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi dl_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    (uint16_t)PktType::NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    dl_tinit,
    dl_tterm,
    dl_ctor,
    dl_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dl_api.base,
    nullptr
};

