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

AppIdHttpSession::AppIdHttpSession(AppIdSession& session)
    : asd(session)
{
}

AppIdHttpSession::~AppIdHttpSession()
{
    delete xff_addr;
    if (host)
        delete host;
    if (url)
        delete url;
    if (uri)
        delete uri;
    if (referer)
        delete referer;
    if (useragent)
        delete useragent;
    if (via)
        delete via;
    if (cookie)
        delete cookie;
    if (body)
        delete body;
    if (response_code)
        delete response_code;
    if (content_type)
        delete content_type;
    if (location)
        delete location;
    if (req_body)
        delete req_body;
    if (server)
        delete server;
    if (x_working_with)
        delete x_working_with;
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

static void replace_header_data(const std::string*& header, const uint8_t* content, int32_t clen)
{
    if (clen <= 0)
        return;

    if (header)
        delete header;
    header=new std::string((const char*)content,clen);
}

void AppIdHttpSession::update_host(const uint8_t* new_host, int32_t len)
{
    replace_header_data(host, new_host, len);
}

void AppIdHttpSession::update_uri(const uint8_t* new_uri, int32_t len)
{
    replace_header_data(uri, new_uri, len);
}

void AppIdHttpSession::update_url()
{
    if (host and uri)
    {
        if (url)
            delete url;
        url=new std::string(std::string("http://") + *host + *uri);
    }
}

void AppIdHttpSession::update_useragent(const uint8_t* new_ua, int32_t len)
{
    replace_header_data(useragent, new_ua, len);
}

void AppIdHttpSession::update_cookie(const uint8_t* new_cookie, int32_t len)
{
    replace_header_data(cookie, new_cookie, len);
}

void AppIdHttpSession::update_referer(const uint8_t* new_referer, int32_t len)
{
    replace_header_data(referer, new_referer, len);
}

void AppIdHttpSession::update_x_working_with(const uint8_t* new_xww, int32_t len)
{
    replace_header_data(x_working_with, new_xww, len);
}

void AppIdHttpSession::update_content_type(const uint8_t* new_content_type, int32_t len)
{
    replace_header_data(content_type, new_content_type, len);
}

void AppIdHttpSession::update_location(const uint8_t* new_location, int32_t len)
{
    replace_header_data(location, new_location, len);
}

void AppIdHttpSession::update_server(const uint8_t* new_server, int32_t len)
{
    replace_header_data(server, new_server, len);
}

void AppIdHttpSession::update_via(const uint8_t* new_via, int32_t len)
{
    replace_header_data(via, new_via, len);
}

void AppIdHttpSession::update_body(const uint8_t* new_body, int32_t len)
{
    replace_header_data(body, new_body, len);
}

void AppIdHttpSession::update_req_body(const uint8_t* new_req_body, int32_t len)
{
    replace_header_data(req_body, new_req_body, len);
}

void AppIdHttpSession::update_response_code(const char* new_rc)
{
    if ( response_code )
        delete response_code;
    response_code = new std::string((char*)new_rc);
}

void AppIdHttpSession::set_url(const char* url)
{
    if ( this->url )
        delete this->url;
    if ( url )
        this->url = new std::string(url);   // FIXIT-M null terminated?
    else
        this->url = nullptr;
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
        content_type = new std::string(CONTENT_TYPE);
        cookie = new std::string(COOKIE);
        host = new std::string(HOST);
        location = new std::string(LOCATION);
        referer = new std::string(REFERER);
        response_code = new std::string(RESPONSE_CODE);
        server = new std::string(SERVER);
        url = new std::string(URL);
        uri = new std::string(URI);
        useragent = new std::string(USERAGENT);
        via = new std::string(VIA);
        x_working_with = new std::string(X_WORKING_WITH);
        body = new std::string(RSP_BODY);
        req_body = new std:: string(REQ_BODY);
        http_fields[REQ_URI_FID].start_offset = URI_OFFSET;
        http_fields[REQ_URI_FID].end_offset = URI_OFFSET + strlen(URI);
        http_fields[REQ_COOKIE_FID].start_offset = COOKIE_OFFSET;
        http_fields[REQ_COOKIE_FID].end_offset = COOKIE_OFFSET + strlen(NEW_COOKIE);
    }

    void init_hsession_new_fields()
    {
        http_fields[REQ_AGENT_FID].field = USERAGENT;
        http_fields[REQ_HOST_FID].field = HOST;
        http_fields[REQ_REFERER_FID].field = REFERER;
        http_fields[REQ_URI_FID].field = URI;
        http_fields[REQ_COOKIE_FID].field = NEW_COOKIE;
        http_fields[REQ_BODY_FID].field = REQ_BODY;
        http_fields[RSP_CONTENT_TYPE_FID].field = CONTENT_TYPE;
        http_fields[RSP_LOCATION_FID].field = LOCATION;
        http_fields[RSP_BODY_FID].field = RSP_BODY;
    }

    void reset()
    {
        delete content_type;
        content_type = nullptr;

        delete cookie;
        cookie = nullptr;

        delete host;
        host = nullptr;

        delete location;
        location = nullptr;

        delete referer;
        referer = nullptr;

        delete response_code;
        response_code = nullptr;

        delete server;
        server = nullptr;

        delete url;
        url = nullptr;

        delete uri;
        uri = nullptr;

        delete useragent;
        useragent = nullptr;

        delete via;
        via = nullptr;

        delete x_working_with;
        x_working_with = nullptr;

        delete body;
        body = nullptr;

        delete req_body;
        req_body = nullptr;
    }

    static AppIdHttpSession* init_http_session(AppIdSession& asd)
    {
        AppIdHttpSession* hsession = new MockAppIdHttpSession(asd);

        return hsession;
    }
};

#endif

