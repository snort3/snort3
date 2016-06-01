//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/**
**  @file       hi_ui_config.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains library calls to configure HttpInspect.
**
**
**  This file deals with configuring HttpInspect processing.  It contains
**  routines to set a default configuration, add server configurations, etc.
**
**  NOTES:
**
**  - 2.10.03:  Initial Developments.  DJR
**  - 2.4.05:   Added tab_uri_delimiter config option.  AJM.
*/
#include "hi_ui_config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "utils/util.h"
#include "hi_return_codes.h"
#include "hi_cmd_lookup.h"

HTTPINSPECT_GLOBAL_CONF::HTTPINSPECT_GLOBAL_CONF()
{
    memset(this, 0, sizeof(*this));
    hi_ui_config_init_global_conf(this);
}

HTTPINSPECT_GLOBAL_CONF::~HTTPINSPECT_GLOBAL_CONF()
{
    if ( iis_unicode_map_filename )
        snort_free(iis_unicode_map_filename);

    if ( iis_unicode_map )
        snort_free(iis_unicode_map);

    if (decode_conf)
        delete(decode_conf);
}

HTTPINSPECT_CONF::HTTPINSPECT_CONF()
{
    // can't just zero the whole thing because of embedded objects
    // FIXIT-L really need explicit assignments or refactor into substruct(s)
    // that can simply be zeroed
    uint8_t* end = (uint8_t*)&whitespace;
    unsigned len = end - (uint8_t*)this;
    memset(this, 0, len);

    hi_ui_config_default(this);
    http_cmd_lookup_init(&cmd_lookup);
}

HTTPINSPECT_CONF::~HTTPINSPECT_CONF()
{
    snort_free(iis_unicode_map_filename);
    snort_free(iis_unicode_map);

    http_cmd_lookup_cleanup(&cmd_lookup);
}

int hi_ui_config_init_global_conf(HTTPINSPECT_GLOBAL_CONF* gc)
{
    gc->compr_depth = 65535;
    gc->decompr_depth = 65535;
    gc->memcap = 150994944;
    gc->max_gzip_mem = 838860;
    if (!gc->decode_conf)
        gc->decode_conf = new DecodeConfig;
    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_config_default::
*/
/**
**  This function sets the global and the global_server default configuration.
**
**  In order to change the default configuration of HttpInspect, you must
**  change this function.
**
**  @param GlobalConf pointer to the global configuration structure
**
**  @return integer
**
**  @retval HI_INVALID_ARG  Fatal Error.  Undefined pointer to GlobalConf
**  @retval HI_MEM_ALLOC_FAIL Fatal Error.  Memory Allocation Failed
*/
int hi_ui_config_default(HTTPINSPECT_CONF* global_server)
{
    global_server->extract_gzip = 1;
    global_server->unlimited_decompress = 1;
    global_server->inspect_response = 1;
    global_server->enable_cookie = 1;
    global_server->normalize_utf = 1;
    global_server->normalize_javascript = 1;
    global_server->non_strict = 1;

    global_server->server_flow_depth = 0;
    global_server->client_flow_depth = 0;
    global_server->post_depth = 65495;

    global_server->chunk_length = 500000;

    global_server->u_encoding.on = 1;

    global_server->whitespace[9] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;   /*
                                                                                               horizontal
                                                                                               tab
                                                                                               */
    global_server->whitespace[11] = HI_UI_CONFIG_WS_BEFORE_URI;  /* vertical tab */
    global_server->whitespace[12] = HI_UI_CONFIG_WS_BEFORE_URI;  /* form feed */
    global_server->whitespace[13] = HI_UI_CONFIG_WS_BEFORE_URI;  /* carriage return */

    global_server->max_hdr_len = 750;
    global_server->max_headers = 100;
    global_server->max_spaces = 200;
    global_server->max_js_ws = 200;
    global_server->long_dir = 500;

    global_server->small_chunk_length.size = 10;
    global_server->small_chunk_length.num = 5;

    return HI_SUCCESS;
}

void HttpInspectCleanupHttpMethodsConf(void* HttpMethods)
{
    HTTP_CMD_CONF* HTTPMethods = (HTTP_CMD_CONF*)HttpMethods;

    snort_free(HTTPMethods);
}

