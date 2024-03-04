//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// kaizen_inspector.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "kaizen_inspector.h"

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

#include "kaizen_engine.h"

using namespace snort;
using namespace std;

THREAD_LOCAL KaizenStats kaizen_stats;
THREAD_LOCAL ProfileStats kaizen_prof;

//--------------------------------------------------------------------------
// HTTP body event handler
//--------------------------------------------------------------------------

class HttpBodyHandler : public DataHandler
{
public:
    HttpBodyHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent& de, Flow*) override;

private:
    Kaizen& inspector;
};

void HttpBodyHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    BinaryClassifier* classifier = KaizenEngine::get_classifier();
    KaizenConfig config = inspector.get_config();
    HttpRequestBodyEvent* he = (HttpRequestBodyEvent*)&de;

    if (he->is_mime())
        return;

    int32_t body_len = 0;

    const char* body = (const char*)he->get_client_body(body_len);

    body_len = std::min(config.client_body_depth, body_len);

    if (!body || body_len <= 0)
        return;

    assert(classifier);

    float output = 0.0;

    kaizen_stats.libml_calls++;

    if (!classifier->run(body, (size_t)body_len, output))
        return;

    kaizen_stats.client_body_bytes += body_len;

    debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "input (body): %.*s\n", body_len, body);
    debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "output: %f\n", static_cast<double>(output));

    if ((double)output > config.http_param_threshold)
    {
        kaizen_stats.client_body_alerts++;
        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "<ALERT>\n");
        DetectionEngine::queue_event(KZ_GID, KZ_SID);
    }
}

//--------------------------------------------------------------------------
// HTTP uri event handler
//--------------------------------------------------------------------------

class HttpUriHandler : public DataHandler
{
public:
    HttpUriHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent&, Flow*) override;

private:
    Kaizen& inspector;
};

void HttpUriHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    BinaryClassifier* classifier = KaizenEngine::get_classifier();
    KaizenConfig config = inspector.get_config();
    HttpEvent* he = (HttpEvent*)&de;

    int32_t query_len = 0;
    const char* query = (const char*)he->get_uri_query(query_len);

    query_len = std::min(config.uri_depth, query_len);

    if (!query || query_len <= 0)
        return;

    assert(classifier);

    float output = 0.0;

    kaizen_stats.libml_calls++;

    if (!classifier->run(query, (size_t)query_len, output))
        return;

    kaizen_stats.uri_bytes += query_len;

    debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "input (query): %.*s\n", query_len, query);
    debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "output: %f\n", static_cast<double>(output));

    if ((double)output > config.http_param_threshold)
    {
        kaizen_stats.uri_alerts++;
        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "<ALERT>\n");
        DetectionEngine::queue_event(KZ_GID, KZ_SID);
    }
}

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

void Kaizen::show(const SnortConfig*) const
{
    ConfigLogger::log_value("uri_depth", config.uri_depth);
    ConfigLogger::log_value("client_body_depth", config.client_body_depth);
    ConfigLogger::log_value("http_param_threshold", config.http_param_threshold);
}

bool Kaizen::configure(SnortConfig* sc)
{
    if (config.uri_depth > 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_HEADER, new HttpUriHandler(*this));

    if (config.client_body_depth > 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_BODY, new HttpBodyHandler(*this));

    if(!InspectorManager::get_inspector(KZ_ENGINE_NAME, true, sc))
    {
        ParseError("snort_ml requires %s to be configured in the global policy.", KZ_ENGINE_NAME);
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KaizenModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* kaizen_ctor(Module* m)
{
    KaizenModule* km = (KaizenModule*)m;
    return new Kaizen(km->get_conf());
}

static void kaizen_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi kaizen_api =
{
    {
#if defined(HAVE_LIBML) || defined(REG_TEST)
        PT_INSPECTOR,
#else
        PT_MAX,
#endif
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        KZ_NAME,
        KZ_HELP,
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
    kaizen_ctor,
    kaizen_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_kaizen[] =
#endif
{
    &kaizen_api.base,
    nullptr
};
