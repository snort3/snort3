/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

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

#include "hi_return_codes.h"
#include "hi_util_xmalloc.h"
#include "hi_cmd_lookup.h"

HTTPINSPECT_GLOBAL_CONF::HTTPINSPECT_GLOBAL_CONF()
{
    memset(this, 0, sizeof(*this));
}

HTTPINSPECT_GLOBAL_CONF::~HTTPINSPECT_GLOBAL_CONF()
{
    if ( iis_unicode_map_filename )
        free(iis_unicode_map_filename);

    if ( iis_unicode_map )
        free(iis_unicode_map);
}

HTTPINSPECT_CONF::HTTPINSPECT_CONF()
{
    // can't just zero the whole thing because of embedded objects
    // FIXIT really need explicit assignments or refactor into substruct(s)
    // that can simply be zeroed
    uint8_t* end = (uint8_t*)&ports;
    unsigned len = end - (uint8_t*)this;
    memset(this, 0, len);

    http_cmd_lookup_init(&cmd_lookup);
}

HTTPINSPECT_CONF::~HTTPINSPECT_CONF()
{
    // FIXIT xfree() etc should go
    xfree(iis_unicode_map_filename);
    xfree(iis_unicode_map);

    http_cmd_lookup_cleanup(&cmd_lookup);
}

/*
**  NAME
**    hi_ui_config_init_global_conf::
*/
/**
**  Initialize the HttpInspect global configuration.
**
**  The main point of this function is to initialize the server
**  lookup type.  We also do things like memset, etc.
**
**  @param GlobalConf pointer to the global configuration
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL could not allocate memory
*/
int hi_ui_config_init_global_conf(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    /* Set Global Configurations */
    GlobalConf->inspection_type = HI_UI_CONFIG_STATELESS;

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
int hi_ui_config_default(HTTPINSPECT_CONF *global_server)
{
    if (global_server == NULL)
    {
        return HI_INVALID_ARG;
    }

    /*
    **  Set Global Server Configurations
    */
    global_server->port_count = 1;
    global_server->ports[10] = 1; /* sets port 80 */

    global_server->server_flow_depth = 300;
    global_server->client_flow_depth = 300;

    global_server->post_depth = -1;

    global_server->chunk_length = 500000;

    global_server->ascii.on = 1;

    global_server->utf_8.on = 1;

    global_server->multiple_slash.on = 1;

    global_server->directory.on = 1;

    global_server->webroot.on = 1;
    global_server->webroot.alert = 1;

    global_server->apache_whitespace.on = 1;

    global_server->iis_delimiter.on = 1;

    global_server->non_strict = 1;

    global_server->whitespace[9] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;   /* horizontal tab */
    global_server->whitespace[11] = HI_UI_CONFIG_WS_BEFORE_URI;  /* vertical tab */
    global_server->whitespace[12] = HI_UI_CONFIG_WS_BEFORE_URI;  /* form feed */
    global_server->whitespace[13] = HI_UI_CONFIG_WS_BEFORE_URI;  /* carriage return */

    global_server->max_hdr_len = HI_UI_CONFIG_MAX_HDR_DEFAULT;
    global_server->max_headers = HI_UI_CONFIG_MAX_HEADERS_DEFAULT;
    global_server->max_spaces = HI_UI_CONFIG_MAX_SPACES_DEFAULT;
    global_server->max_js_ws = HI_UI_CONFIG_MAX_SPACES_DEFAULT;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_config_reset_global::
*/
/**
**  This function resets the global parameters, THIS IS NOT THE GLOBAL
**  SERVER CONFIGURATION.
**
**  @param GlobalConf pointer to the global configuration structure
**
**  @return integer
**
**  @return HI_SUCCESS function successful
*/
int hi_ui_config_reset_global(HTTPINSPECT_GLOBAL_CONF *GlobalConf)
{
    GlobalConf->inspection_type = 0;
    GlobalConf->iis_unicode_map = 0;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_set_profile_apache::
*/
/**
**  Set an HTTPINSPECT_CONF to mimic apache configuration.
**
**  This sets a server configuration to imitate an apache web server,
**  and should reduce false positives against systems on which certain
**  attacks or evasions do not work.  We hope to still log an event,
**  but one that is less priority.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_apache(HTTPINSPECT_CONF *ServerConf)
{
    ServerConf->server_flow_depth = 300;
    ServerConf->client_flow_depth = 300;
    ServerConf->post_depth = -1;

    ServerConf->non_strict = 1;

    ServerConf->chunk_length = 500000;

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->webroot.on = 1;
    ServerConf->webroot.alert = 1;

    ServerConf->apache_whitespace.on = 1;

    ServerConf->utf_8.on = 1;

    ServerConf->normalize_utf = 1;
    ServerConf->normalize_javascript = 0;

    ServerConf->whitespace[9] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;   /* horizontal tab */
    ServerConf->whitespace[11] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;  /* vertical tab */
    ServerConf->whitespace[12] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;  /* form feed */
    ServerConf->whitespace[13] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;  /* carriage return */

    ServerConf->max_hdr_len = HI_UI_CONFIG_MAX_HDR_DEFAULT;
    ServerConf->max_headers = HI_UI_CONFIG_MAX_HEADERS_DEFAULT;
    ServerConf->max_spaces = HI_UI_CONFIG_MAX_SPACES_DEFAULT;
    ServerConf->max_js_ws = HI_UI_CONFIG_MAX_SPACES_DEFAULT;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_set_profile_iis::
*/
/**
**  Set an HTTPINSPECT_CONF to mimic IIS configuration.
**
**  This sets a server configuration to imitate an IIS web server,
**  and should reduce false positives against systems on which certain
**  attacks or evasions do not work.  We hope to still log an event,
**  but one that is less priority.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_iis(HTTPINSPECT_CONF *ServerConf,
                                 uint8_t* iis_unicode_map)
{
    if(iis_unicode_map == NULL)
    {
        return HI_INVALID_ARG;
    }

    ServerConf->server_flow_depth = 300;
    ServerConf->client_flow_depth = 300;
    ServerConf->post_depth = -1;

    ServerConf->chunk_length = 500000;

    ServerConf->iis_unicode_map = iis_unicode_map;

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->webroot.on = 1;
    ServerConf->webroot.alert = 1;

    ServerConf->double_decoding.on    = 0;
    ServerConf->double_decoding.alert = 0;

    ServerConf->u_encoding.on         = 1;
    ServerConf->u_encoding.alert      = 1;

    ServerConf->bare_byte.on          = 1;
    ServerConf->bare_byte.alert       = 1;

    ServerConf->iis_unicode.on        = 1;
    ServerConf->iis_unicode.alert     = 1;

    ServerConf->iis_backslash.on      = 1;

    ServerConf->iis_delimiter.on      = 1;

    ServerConf->apache_whitespace.on  = 1;

    ServerConf->non_strict = 1;

    ServerConf->normalize_utf = 1;
    ServerConf->normalize_javascript = 0;

    ServerConf->whitespace[9] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;   /* horizontal tab */
    ServerConf->whitespace[11] = HI_UI_CONFIG_WS_BEFORE_URI;  /* vertical tab */
    ServerConf->whitespace[12] = HI_UI_CONFIG_WS_BEFORE_URI;  /* form feed */
    ServerConf->whitespace[13] = HI_UI_CONFIG_WS_BEFORE_URI;  /* carriage return */

    ServerConf->max_hdr_len = HI_UI_CONFIG_MAX_HDR_DEFAULT;
    ServerConf->max_headers = HI_UI_CONFIG_MAX_HEADERS_DEFAULT;
    ServerConf->max_spaces = HI_UI_CONFIG_MAX_SPACES_DEFAULT;
    ServerConf->max_js_ws = HI_UI_CONFIG_MAX_SPACES_DEFAULT;

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_set_profile_iis_4or5::
*/
/**
** Double decoding decoding attacks exist for IIS
** 4.0 and 5.0, but not 5.1 and beyond.
**
** This function uses the general IIS setup, hi_ui_config_set_profile_iis,
** but set the double_decoding flags.
**/

int hi_ui_config_set_profile_iis_4or5(HTTPINSPECT_CONF *ServerConf,
                                 uint8_t* iis_unicode_map)
{
    int ret;

    ret = hi_ui_config_set_profile_iis(ServerConf, iis_unicode_map);

    ServerConf->double_decoding.on = 1;
    ServerConf->double_decoding.alert = 1;

    return ret;
}

/*
**  NAME
**    hi_ui_set_profile_all::
*/
/**
**  Set an HTTPINSPECT_CONF to catch all attacks and evasions.
**
**  This basically turns on all the tricks and most of the
**  alerts, so you won't miss anything that HttpInspect does.
**
**  @param ServerConf pointer to structure HTTPINSPECT_CONF
**
**  @return integer
**
**  @retval HI_SUCCESS function successful
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_config_set_profile_all(HTTPINSPECT_CONF *ServerConf,
                                 uint8_t* iis_unicode_map)
{
    if(iis_unicode_map == NULL)
    {
        return HI_INVALID_ARG;
    }

    ServerConf->server_flow_depth   = 300;
    ServerConf->client_flow_depth   = 300;
    ServerConf->post_depth = -1;

    ServerConf->chunk_length = 500000;

    ServerConf->iis_unicode_map = iis_unicode_map;

    ServerConf->ascii.on = 1;

    ServerConf->multiple_slash.on = 1;

    ServerConf->directory.on = 1;

    ServerConf->webroot.on = 1;
    ServerConf->webroot.alert = 1;

    ServerConf->double_decoding.on    = 1;
    ServerConf->double_decoding.alert = 1;

    ServerConf->u_encoding.on         = 1;
    ServerConf->u_encoding.alert      = 1;

    ServerConf->bare_byte.on          = 1;
    ServerConf->bare_byte.alert       = 1;

    ServerConf->iis_unicode.on        = 1;
    ServerConf->iis_unicode.alert     = 1;

    ServerConf->iis_backslash.on      = 1;

    ServerConf->iis_delimiter.on      = 1;

    ServerConf->apache_whitespace.on     = 1;

    ServerConf->non_strict = 1;

    ServerConf->normalize_utf = 1;
    ServerConf->normalize_javascript = 0;

    ServerConf->whitespace[9] = HI_UI_CONFIG_WS_BEFORE_URI | HI_UI_CONFIG_WS_AFTER_URI;   /* horizontal tab */
    ServerConf->whitespace[11] = HI_UI_CONFIG_WS_BEFORE_URI;  /* vertical tab */
    ServerConf->whitespace[12] = HI_UI_CONFIG_WS_BEFORE_URI;  /* form feed */
    ServerConf->whitespace[13] = HI_UI_CONFIG_WS_BEFORE_URI;  /* carriage return */

    ServerConf->max_hdr_len = HI_UI_CONFIG_MAX_HDR_DEFAULT;
    ServerConf->max_headers = HI_UI_CONFIG_MAX_HEADERS_DEFAULT;
    ServerConf->max_spaces = HI_UI_CONFIG_MAX_SPACES_DEFAULT;
    ServerConf->max_js_ws = HI_UI_CONFIG_MAX_SPACES_DEFAULT;

    return HI_SUCCESS;
}

void HttpInspectCleanupHttpMethodsConf(void *HttpMethods)
{
    HTTP_CMD_CONF *HTTPMethods = (HTTP_CMD_CONF *)HttpMethods;

    free(HTTPMethods);
}

