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

// appid_mock_http_session.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_HTTP_SESSION_H_
#define APPID_MOCK_HTTP_SESSION_H_

AppIdHttpSession::AppIdHttpSession(AppIdSession* session) : asd(session) { }
AppIdHttpSession::~AppIdHttpSession()
{
    snort_free(body);
    snort_free(content_type);
    snort_free(cookie);
    snort_free(host);
    snort_free(location);
    snort_free(referer);
    snort_free(req_body);
    snort_free(response_code);
    snort_free(server);
    snort_free(uri);
    snort_free(url);
    snort_free(useragent);
    snort_free(via);
    snort_free(x_working_with);
    delete xffAddr;

    if (new_field_contents)
        for ( unsigned i = 0; i < NUMBER_OF_PTYPES; i++)
            if (nullptr != new_field[i])
                snort_free(new_field[i]);
}

int AppIdHttpSession::process_http_packet(int) { return 0; }

char const* APPID_UT_XFF_IP_ADDR = "192.168.0.1";
char const* CONTENT_TYPE = "html/text";
char const* COOKIE = "this is my request cookie content";
char const* NEW_COOKIE = "request new cookie content is chocolate chip";
char const* HOST = "www.google.com";
char const* LOCATION = "abc.yahoo.com";
char const* URL = "https://www.google.com/path/to/index.html";
char const* URI = "/path/to/index.html";
char const* USERAGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X)";
char const* REFERER = "http://www.yahoo.com/search";
char const* SERVER = "Apache";
char const* X_WORKING_WITH = "working with string";
char const* VIA = "via string";
char const* RESPONSE_CODE = "301";
char const* REQ_BODY = "this is the body of the http request";
char const* RSP_BODY = "this is the body of the http response";

#define URI_OFFSET 22
#define COOKIE_OFFSET 44

void init_hsession_new_fields(AppIdHttpSession* hsession)
{
    hsession->new_field_contents = true;
    hsession->new_field[REQ_AGENT_FID] = snort_strdup((char*)(USERAGENT));
    hsession->new_field[REQ_HOST_FID] = snort_strdup((char*)(HOST));
    hsession->new_field[REQ_REFERER_FID] = snort_strdup((char*)(REFERER));
    hsession->new_field[REQ_URI_FID] = snort_strdup((char*)(URI));
    hsession->new_field[REQ_COOKIE_FID] = snort_strdup((char*)(NEW_COOKIE));
    hsession->new_field[REQ_BODY_FID] = snort_strdup((char*)(REQ_BODY));
    hsession->new_field[RSP_CONTENT_TYPE_FID] = snort_strdup((char*)(CONTENT_TYPE));
    hsession->new_field[RSP_LOCATION_FID] = snort_strdup((char*)(LOCATION));
    hsession->new_field[RSP_BODY_FID] = snort_strdup((char*)(RSP_BODY));
}

AppIdHttpSession* init_http_session(AppIdSession* asd)
{
    AppIdHttpSession* hsession = new AppIdHttpSession(asd);
    SfIp* ip = new SfIp;
    ip->pton(AF_INET, APPID_UT_XFF_IP_ADDR);
    hsession->xffAddr = ip;
    hsession->content_type = snort_strdup((char*)(CONTENT_TYPE));
    hsession->cookie = snort_strdup((char*)(COOKIE));
    hsession->host = snort_strdup((char*)(HOST));
    hsession->location = snort_strdup((char*)(LOCATION));
    hsession->referer = snort_strdup((char*)(REFERER));
    hsession->response_code = snort_strdup((char*)(RESPONSE_CODE));
    hsession->server = snort_strdup((char*)(SERVER));
    hsession->url = snort_strdup((char*)(URL));
    hsession->uri = snort_strdup((char*)(URI));
    hsession->useragent = snort_strdup((char*)(USERAGENT));
    hsession->via = snort_strdup((char*)(VIA));
    hsession->x_working_with = snort_strdup((char*)(X_WORKING_WITH));
    hsession->body = snort_strdup((char*)(RSP_BODY));
    hsession->req_body = snort_strdup((char*)(REQ_BODY));
    hsession->fieldOffset[REQ_URI_FID] = URI_OFFSET;
    hsession->fieldEndOffset[REQ_URI_FID] = URI_OFFSET + strlen(URI);
    hsession->fieldOffset[REQ_COOKIE_FID] = COOKIE_OFFSET;
    hsession->fieldEndOffset[REQ_COOKIE_FID] = COOKIE_OFFSET + strlen(NEW_COOKIE);

    return hsession;
}

#endif

