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

// dce_http_proxy_splitter.cc author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_http_proxy_splitter.h"

#include "dce_http_proxy_module.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// NOTE:  These strings must have a length of at least one character
#define HTTP_PROXY_REQUEST    "RPC_CONNECT"
#define HTTP_PROXY_RESPONSE   "HTTP/1."

const StreamBuffer DceHttpProxySplitter::reassemble(
    Flow* flow, unsigned total, unsigned offset,
    const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    // FIXIT-M Framework should permit the null return on both PDU directions
    if ( to_server() )
    {
        copied = len;
        return { nullptr, 0 };
    }
    else
        return StreamSplitter::reassemble(flow,total,offset,data,len,flags,copied);
}

StreamSplitter::Status DceHttpProxySplitter::scan(
    Flow*, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    StreamSplitter::Status status;

    if ( (flags & PKT_FROM_CLIENT) != 0 )
        status =  match_request_head( data, len );
    else if ( (flags & PKT_FROM_SERVER) != 0 )
        status = match_response( data, len );
    else
        return StreamSplitter::ABORT;

    if ( status == StreamSplitter::FLUSH )
    {
        *fp = len;
    }
    return status;
}

/* match_request_head() is only used by the c2s splitter instance. */
StreamSplitter::Status
    DceHttpProxySplitter::match_request_head(const uint8_t* data, uint32_t& len)
{
    if ( match_index == (unsigned int)strlen(HTTP_PROXY_REQUEST) )
    {
        cutover = true;
        return StreamSplitter::FLUSH;
    }

    len = (len > strlen(HTTP_PROXY_REQUEST)) ? strlen(HTTP_PROXY_REQUEST) : len;

    if ( ((len+match_index) > strlen(HTTP_PROXY_REQUEST)) ||
        memcmp( (const void*)data, (const void*)(&HTTP_PROXY_REQUEST[match_index]), len ) != 0 )
        return StreamSplitter::ABORT;
    else
    {
        match_index += len;
        if ( match_index == (unsigned int)strlen(HTTP_PROXY_REQUEST) )
        {
            return StreamSplitter::FLUSH;
        }
        else
            return StreamSplitter::SEARCH;
    }
}

/* match_response_head() is only used by the s2c splitter instance. */
StreamSplitter::Status DceHttpProxySplitter::match_response_head(const uint8_t* data, uint32_t& len)
{
    assert(strlen(HTTP_PROXY_RESPONSE) > 0); // make sure we have a string to match

    len = (len > strlen(HTTP_PROXY_RESPONSE)) ? strlen(HTTP_PROXY_RESPONSE) : len;

    if ( memcmp( (const void*)data, (const void*)(&HTTP_PROXY_RESPONSE[match_index]), len ) != 0 )
        return StreamSplitter::ABORT;
    else
    {
        match_index += len;
        return match_index == (unsigned int)strlen(HTTP_PROXY_RESPONSE) ?
            StreamSplitter::FLUSH : StreamSplitter::SEARCH;
    }
}

/* match_request() is only used by the s2c splitter instance. */
StreamSplitter::Status
    DceHttpProxySplitter::match_response(const uint8_t* data, uint32_t& len)
{
    uint32_t starting_index = 0;

    if ( match_state == HTTP_PROXY_INIT )
    {
        uint32_t my_len = len;
        StreamSplitter::Status status = match_response_head(data, my_len);
        if ( status != StreamSplitter::FLUSH )
            return status;
        starting_index = my_len;
        match_state = HTTP_PROXY_HEAD;
    }

    for ( unsigned int i=starting_index; i<len; i++ )
    {
        // Skip any optional '\r's while parsing
        if ( data[i] == '\r' )
            continue;
        if ( data[i] == '\n' )
        {
            if ( match_state ==  HTTP_PROXY_HEAD )
                match_state = HTTP_PROXY_FIRST_NL;
            else
            {
                cutover = true;
                return StreamSplitter::FLUSH;
            }
        }
        else
            match_state = HTTP_PROXY_HEAD;
    }
    return StreamSplitter::SEARCH;
}

DceHttpProxySplitter::DceHttpProxySplitter(bool c2s) : StreamSplitter(c2s)
{
    cutover = false;
    match_index = 0;
    match_state = HTTP_PROXY_INIT;
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("DceHttpProxySplitter-scan - first_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"RPC", 3, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - first_proxy_request_no_direction", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"RPC", 3, 0, &fp) == StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - bad_first_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"xxx", 1, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - first_bad_second_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"RPC", 3, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"R", 1, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - first_good_second_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"RPC", 3, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"_CON", 4, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - full_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    Flow* flow = new Flow();
    uint32_t fp = 0;

    REQUIRE(splitter->scan(flow, (const uint8_t*)HTTP_PROXY_REQUEST,
        strlen(HTTP_PROXY_REQUEST), PKT_FROM_CLIENT, &fp) == StreamSplitter::FLUSH);
    REQUIRE(fp == strlen(HTTP_PROXY_REQUEST));
    REQUIRE(splitter->scan(flow, (const uint8_t*)"0", 1, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::FLUSH);
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - extra_proxy_request", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(true);
    const char* extra = "ignore";
    char* string = new char[strlen(HTTP_PROXY_REQUEST)+strlen(extra)+1];
    Flow* flow = new Flow();
    uint32_t fp = 0;
    strncpy(string,(const char*)HTTP_PROXY_REQUEST,strlen(HTTP_PROXY_REQUEST));
    strncpy(string+strlen(HTTP_PROXY_REQUEST),extra,strlen(extra));

    REQUIRE(splitter->scan(flow, (const uint8_t*)string,
        (strlen(HTTP_PROXY_REQUEST)+strlen(extra)), PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::FLUSH);
    REQUIRE(fp == strlen(HTTP_PROXY_REQUEST));
    REQUIRE(splitter->scan(flow, (const uint8_t*)"0", 1, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::FLUSH);
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
    delete[] string;
}

TEST_CASE("DceHttpProxySplitter-scan - first_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"xxx", 3, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - good_1_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp = 0;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.xxx\n\n", 12,
        PKT_FROM_SERVER, &fp) == StreamSplitter::FLUSH);
    REQUIRE((fp == 12));
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - good_2_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp = 0;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.xxx\nxx\n\n", 15,
        PKT_FROM_SERVER, &fp) == StreamSplitter::FLUSH);
    REQUIRE((fp == 15));
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
}
TEST_CASE("DceHttpProxySplitter-scan - good_3_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp = 0;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.xxx\nxx\n\nyyy", 18,
        PKT_FROM_SERVER, &fp) == StreamSplitter::FLUSH);
    REQUIRE((fp == 18));
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - bad_1_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.xxx\nx\n", 13, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - bad_2_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.xxx\nx", 12, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpProxySplitter-scan - bad_3_proxy_response", "[http_proxy_splitter]")
{
    DceHttpProxySplitter* splitter = new DceHttpProxySplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"HTTP/1.", 7, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

#endif
