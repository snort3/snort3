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

// dce_http_server_splitter.cc author Ed Borgoyn <eborgoyn@cisco.com>
// based on work by Todd Wease

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dce_http_server_splitter.h"

#include "dce_http_server_module.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

// NOTE:  These strings must have a length of at least one character
#define HTTP_SERVER_MARKER "ncacn_http/1.0"

StreamSplitter::Status DceHttpServerSplitter::scan(
    Flow*, const uint8_t* data, uint32_t len, uint32_t flags, uint32_t* fp)
{
    if ( (flags & PKT_FROM_CLIENT) != 0 )
        return StreamSplitter::ABORT;

    StreamSplitter::Status status = match(data, len);

    if ( status == StreamSplitter::FLUSH )
    {
        cutover = true;
        *fp = len;
    }
    return status;
}

StreamSplitter::Status DceHttpServerSplitter::match(const uint8_t* data, uint32_t& len)
{
    assert(strlen(HTTP_SERVER_MARKER) > 0); // make sure we have a string to match

    len = (len > strlen(HTTP_SERVER_MARKER)) ? strlen(HTTP_SERVER_MARKER) : len;

    if ( ((len+match_index) > strlen(HTTP_SERVER_MARKER)) ||
        memcmp( (const void*)data, (const void*)(&HTTP_SERVER_MARKER[match_index]), len ) != 0 )
        return StreamSplitter::ABORT;
    else
    {
        match_index += len;
        return match_index == (unsigned int)strlen(HTTP_SERVER_MARKER) ?
            StreamSplitter::FLUSH : StreamSplitter::SEARCH;
    }
}

DceHttpServerSplitter::DceHttpServerSplitter(bool c2s) : StreamSplitter(c2s)
{
    match_index = 0;
    cutover = false;
}

//--------------------------------------------------------------------------
// unit tests 
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("DceHttpServerSplitter-scan - first_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"n", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - first_server_wrong_direction", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"n", 1, PKT_FROM_CLIENT, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - bad_first_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"x", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - first_bad_second_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"n", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"n", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::ABORT);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - first_good_second_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)"n", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->scan(flow, (const uint8_t*)"c", 1, PKT_FROM_SERVER, &fp) ==
        StreamSplitter::SEARCH);
    REQUIRE(splitter->cutover_inspector() == false);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - full_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    Flow* flow = new Flow();
    uint32_t fp;

    REQUIRE(splitter->scan(flow, (const uint8_t*)HTTP_SERVER_MARKER,
        strlen(HTTP_SERVER_MARKER), PKT_FROM_SERVER, &fp) == StreamSplitter::FLUSH);
    REQUIRE(fp == strlen(HTTP_SERVER_MARKER));
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
}

TEST_CASE("DceHttpServerSplitter-scan - extra_server", "[http_server_splitter]")
{
    DceHttpServerSplitter* splitter = new DceHttpServerSplitter(false);
    const char* extra = "ignore";
    char* string = new char[strlen(HTTP_SERVER_MARKER)+strlen(extra)+1];
    Flow* flow = new Flow();
    uint32_t fp;
    strncpy(string,(const char*)HTTP_SERVER_MARKER,strlen(HTTP_SERVER_MARKER));
    strncpy(string+strlen(HTTP_SERVER_MARKER),extra,strlen(extra));

    REQUIRE(splitter->scan(flow, (const uint8_t*)string,
        (strlen(HTTP_SERVER_MARKER)+strlen(extra)), PKT_FROM_SERVER, &fp) ==
        StreamSplitter::FLUSH);
    REQUIRE(fp == strlen(HTTP_SERVER_MARKER));
    REQUIRE(splitter->cutover_inspector() == true);
    delete flow;
    delete splitter;
    delete[] string;
}

#endif
