//--------------------------------------------------------------------------
// Copyright (C) 2023-2025 Cisco and/or its affiliates. All rights reserved.
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
// snort_ml_inspector.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_ml_inspector.h"

#include <cassert>

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "pub_sub/http_events.h"
#include "pub_sub/http_request_body_event.h"
#include "utils/util.h"

#include "snort_ml_engine.h"

using namespace snort;
using namespace std;

THREAD_LOCAL SnortMLStats snort_ml_stats;
THREAD_LOCAL ProfileStats snort_ml_prof;

//--------------------------------------------------------------------------
// HTTP body event handler
//--------------------------------------------------------------------------

class HttpBodyHandler : public DataHandler
{
public:
    HttpBodyHandler(SnortML& ml)
        : DataHandler(SNORT_ML_NAME), inspector(ml) {}

    void handle(DataEvent& de, Flow*) override;

private:
    SnortML& inspector;
};

void HttpBodyHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(snort_ml_prof);

    libml::BinaryClassifierSet* classifiers = SnortMLEngine::get_classifiers();
    SnortMLConfig config = inspector.get_config();
    HttpRequestBodyEvent* he = (HttpRequestBodyEvent*)&de;

    if (he->is_mime())
        return;

    int32_t body_len = 0;
    const char* body = (const char*)he->get_client_body(body_len);

    if (!body || body_len <= 0)
        return;

    const size_t len = std::min((size_t)config.client_body_depth, (size_t)body_len);

    assert(classifiers);

    float output = 0.0;

    snort_ml_stats.libml_calls++;

    if (!classifiers->run(body, len, output))
        return;

    snort_ml_stats.client_body_bytes += len;

    debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "input (body): %.*s\n", (int)len, body);
    debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "output: %f\n", static_cast<double>(output));

    if ((double)output > config.http_param_threshold)
    {
        snort_ml_stats.client_body_alerts++;
        debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "<ALERT>\n");
        DetectionEngine::queue_event(SNORT_ML_GID, SNORT_ML_SID);
    }
}

//--------------------------------------------------------------------------
// HTTP uri event handler
//--------------------------------------------------------------------------

class HttpUriHandler : public DataHandler
{
public:
    HttpUriHandler(SnortML& ml)
        : DataHandler(SNORT_ML_NAME), inspector(ml) {}

    void handle(DataEvent&, Flow*) override;

private:
    SnortML& inspector;
};

void HttpUriHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(snort_ml_prof);

    libml::BinaryClassifierSet* classifiers = SnortMLEngine::get_classifiers();
    SnortMLConfig config = inspector.get_config();
    HttpEvent* he = (HttpEvent*)&de;

    int32_t query_len = 0;
    const char* query = (const char*)he->get_uri_query(query_len);

    if (!query || query_len <= 0)
        return;

    const size_t len = std::min((size_t)config.uri_depth, (size_t)query_len);

    assert(classifiers);

    float output = 0.0;

    snort_ml_stats.libml_calls++;

    if (!classifiers->run(query, len, output))
        return;

    snort_ml_stats.uri_bytes += len;

    debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "input (query): %.*s\n", (int)len, query);
    debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "output: %f\n", static_cast<double>(output));

    if ((double)output > config.http_param_threshold)
    {
        snort_ml_stats.uri_alerts++;
        debug_logf(snort_ml_trace, TRACE_CLASSIFIER, nullptr, "<ALERT>\n");
        DetectionEngine::queue_event(SNORT_ML_GID, SNORT_ML_SID);
    }
}

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

void SnortML::show(const SnortConfig*) const
{
    ConfigLogger::log_limit("uri_depth", config.uri_depth, -1);
    ConfigLogger::log_limit("client_body_depth", config.client_body_depth, -1);
    ConfigLogger::log_value("http_param_threshold", config.http_param_threshold);
}

bool SnortML::configure(SnortConfig* sc)
{
    if (config.uri_depth != 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_HEADER, new HttpUriHandler(*this));

    if (config.client_body_depth != 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_BODY, new HttpBodyHandler(*this));

    if(!InspectorManager::get_inspector(SNORT_ML_ENGINE_NAME, true, sc))
    {
        ParseError("snort_ml requires %s to be configured in the global policy.", SNORT_ML_ENGINE_NAME);
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SnortMLModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* snort_ml_ctor(Module* m)
{
    SnortMLModule* km = (SnortMLModule*)m;
    return new SnortML(km->get_conf());
}

static void snort_ml_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi snort_ml_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SNORT_ML_NAME,
        SNORT_ML_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,  // proto_bits;
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    snort_ml_ctor,
    snort_ml_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_snort_ml[] =
#endif
{
    &snort_ml_api.base,
    nullptr
};
