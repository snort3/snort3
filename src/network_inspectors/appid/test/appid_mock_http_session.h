//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifndef APPID_MOCK_HTTP_SESSION_H
#define APPID_MOCK_HTTP_SESSION_H

#include <string>

typedef AppIdHttpSession::pair_t pair_t;

AppIdHttpSession::AppIdHttpSession(AppIdSession& session)
    : asd(session)
{
    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
        meta_data[i] = nullptr;
}

AppIdHttpSession::~AppIdHttpSession()
{
    delete xff_addr;

    for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
    {
        if ( meta_data[i] )
            delete meta_data[i];
    }
}

int AppIdHttpSession::process_http_packet(AppidSessionDirection) { return 0; }

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

void AppIdHttpSession::update_url()
{
    const std::string* host = meta_data[REQ_HOST_FID];
    const std::string* uri = meta_data[REQ_URI_FID];
    if (host and uri)
    {
        if (meta_data[MISC_URL_FID])
            delete meta_data[MISC_URL_FID];
        meta_data[MISC_URL_FID] = new std::string(std::string("http://") + *host + *uri);
    }
}

class MockAppIdHttpSession : public AppIdHttpSession
{
public:
    MockAppIdHttpSession(AppIdSession& asd)
        : AppIdHttpSession(asd)
    {
        SfIp* ip = new SfIp;
        ip->pton(AF_INET, APPID_UT_XFF_IP_ADDR);
        xff_addr = ip;

        meta_data[REQ_AGENT_FID] = new std::string(USERAGENT);
        meta_data[REQ_HOST_FID] = new std::string(HOST);
        meta_data[REQ_REFERER_FID] = new std::string(REFERER);
        meta_data[REQ_URI_FID] = new std::string(URI);
        meta_data[REQ_COOKIE_FID] = new std::string(COOKIE);
        meta_data[REQ_BODY_FID] = new std::string(REQ_BODY);
        meta_data[RSP_CONTENT_TYPE_FID] = new std::string(CONTENT_TYPE);
        meta_data[RSP_LOCATION_FID] = new std::string(LOCATION);
        meta_data[RSP_BODY_FID] = new std::string(RSP_BODY);
        meta_data[MISC_VIA_FID] = new std::string(VIA);
        meta_data[MISC_RESP_CODE_FID] = new std::string(RESPONSE_CODE);
        meta_data[MISC_SERVER_FID] = new std::string(SERVER);
        meta_data[MISC_XWW_FID] = new std::string(X_WORKING_WITH);
        meta_data[MISC_URL_FID] = new std::string(URL);

        meta_offset[REQ_URI_FID].first = URI_OFFSET;
        meta_offset[REQ_URI_FID].second = URI_OFFSET + strlen(URI);
        meta_offset[REQ_COOKIE_FID].first = COOKIE_OFFSET;
        meta_offset[REQ_COOKIE_FID].second = COOKIE_OFFSET + strlen(NEW_COOKIE);
    }

    void init_hsession_new_fields()
    {
        set_field(REQ_AGENT_FID, new std::string(USERAGENT));
        set_field(REQ_HOST_FID, new std::string(HOST));
        set_field(REQ_REFERER_FID, new std::string(REFERER));
        set_field(REQ_URI_FID, new std::string(URI));
        set_field(REQ_COOKIE_FID, new std::string(COOKIE));
        set_field(REQ_BODY_FID, new std::string(REQ_BODY));
        set_field(RSP_CONTENT_TYPE_FID, new std::string(CONTENT_TYPE));
        set_field(RSP_LOCATION_FID, new std::string(LOCATION));
        set_field(RSP_BODY_FID, new std::string(RSP_BODY));
    }

    void reset()
    {
        for ( int i = 0; i < NUM_METADATA_FIELDS; i++)
        {
            delete meta_data[i];
            meta_data[i] = nullptr;
        }
    }

    static AppIdHttpSession* init_http_session(AppIdSession& asd)
    {
        AppIdHttpSession* hsession = new MockAppIdHttpSession(asd);

        return hsession;
    }
};

#endif

