//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// detector_http.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "detector_http.h"

// Start of HTTP/2 detection logic.
//
// This is intended to simply detect the presence of HTTP version 2 as a
// service protocol if it is seen (unencrypted) on non-std ports.  That way, we
// can notify Snort for future reference.  this covers the "with prior
// knowledge" case for HTTP/2 (i.e., the client knows the server supports
// HTTP/2 and jumps right in with the preface).

static const char HTTP2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define HTTP2_PREFACE_LEN (sizeof(HTTP2_PREFACE) - 1)
#define HTTP2_PREFACE_MAXPOS (sizeof(HTTP2_PREFACE)-2)

static HttpServiceDetector* http_service_detector;

HttpClientDetector::HttpClientDetector(ClientDiscovery* cdm)
{
    handler = cdm;
    name = "HTTP";
    proto = IpProtocol::TCP;
    minimum_matches = 1;

    tcp_patterns =
    {
        { (const uint8_t*)HTTP2_PREFACE, HTTP2_PREFACE_LEN, 0, 0, APP_ID_HTTP }
    };

    appid_registry =
    {
        { APP_ID_HTTP, 0 }
    };

    handler->register_detector(name, this, proto);
}


int HttpClientDetector::validate(AppIdDiscoveryArgs& args)
{
    add_app(args.asd, APP_ID_HTTP, APP_ID_HTTP + GENERIC_APP_OFFSET, nullptr);
    args.asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
    http_service_detector->add_service(args.asd, args.pkt, args.dir, APP_ID_HTTP);
    args.asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
    args.asd.set_session_flags(APPID_SESSION_CLIENT_DETECTED | APPID_SESSION_SERVICE_DETECTED);
    args.asd.clear_session_flags(APPID_SESSION_CONTINUE);
    args.asd.is_http2 = true;

    return APPID_SUCCESS;
}

HttpServiceDetector::HttpServiceDetector(ServiceDiscovery* sd)
{
    http_service_detector = this;

    handler = sd;
    name = "HTTP";
    proto = IpProtocol::TCP;
    detectorType = DETECTOR_TYPE_DECODER;

    appid_registry =
    {
        { APP_ID_HTTP, 0 }
    };

    handler->register_detector(name, this, proto);
}


int HttpServiceDetector::validate(AppIdDiscoveryArgs&)
{
    return APPID_INPROCESS;
}

// End of HTTP/2 detection logic.

