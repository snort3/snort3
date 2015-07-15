//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
**  Author(s):  Hui Cao <huica@cisco.com>
**
**  NOTES
**  9.25.2012 - Initial Source Code. Hui Cao
*/

#include "file_mime_config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "snort_types.h"
#include "file_api.h"
#include "file_mime_process.h"
#include "sf_email_attach_decode.h"
#include "util.h"
#include "parser.h"

#define CONF_SEPARATORS                  " \t\n\r"
#define CONF_MAX_MIME_MEM                "max_mime_mem"
#define CONF_B64_DECODE                  "b64_decode_depth"
#define CONF_QP_DECODE                   "qp_decode_depth"
#define CONF_BITENC_DECODE               "bitenc_decode_depth"
#define CONF_UU_DECODE                   "uu_decode_depth"

/*These are temporary values*/
#define DEFAULT_MAX_MIME_MEM          838860
#define DEFAULT_MIME_MEMCAP           838860
#define DEFAULT_DEPTH                 1464
#define MAX_LOG_MEMCAP                104857600
#define MIN_LOG_MEMCAP                3276
#define MAX_MIME_MEM                  104857600
#define MIN_MIME_MEM                  3276
#define MAX_DEPTH                     65535
#define MIN_DEPTH                     -1

#define ERRSTRLEN   512

static int ProcessDecodeDepth(
    DecodeConfig* config, char* ErrorString, int ErrStrLen,
    const char* decode_type, DecodeType type, const char* preproc_name)
{
    char* endptr;
    char* value;
    int decode_depth = 0;
    if (config == NULL)
    {
        snprintf(ErrorString, ErrStrLen, "%s config is NULL.\n", preproc_name);
        return -1;
    }

    value = get_tok(NULL, CONF_SEPARATORS);
    if ( value == NULL )
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid format for %s config option '%s'.", preproc_name, decode_type);
        return -1;
    }
    decode_depth = strtol(value, &endptr, 10);

    if (*endptr)
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid format for %s config option '%s'.", preproc_name, decode_type);
        return -1;
    }
    if (decode_depth < MIN_DEPTH || decode_depth > MAX_DEPTH)
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid value for %s config option '%s'."
            "It should range between %d and %d.",
            preproc_name, decode_type, MIN_DEPTH, MAX_DEPTH);
        return -1;
    }

    switch (type)
    {
    case DECODE_B64:
        if ((decode_depth > 0) && (decode_depth & 3))
        {
            decode_depth += 4 - (decode_depth & 3);
            if (decode_depth > MAX_DEPTH )
            {
                decode_depth = decode_depth - 4;
            }
            ParseWarning(WARN_CONF,
                "%s: 'b64_decode_depth' is not a multiple of 4. "
                "Rounding up to the next multiple of 4. The new 'b64_decode_depth' is %d.\n",
                preproc_name, decode_depth);
        }
        config->b64_depth = decode_depth;
        break;
    case DECODE_QP:
        config->qp_depth = decode_depth;
        break;
    case DECODE_UU:
        config->uu_depth = decode_depth;
        break;
    case DECODE_BITENC:
        config->bitenc_depth = decode_depth;
        break;
    default:
        return -1;
    }

    return 0;
}

void set_mime_decode_config_defauts(DecodeConfig* decode_conf)
{
    decode_conf->ignore_data = false;
    decode_conf->max_mime_mem = DEFAULT_MIME_MEMCAP;
    decode_conf->b64_depth = DEFAULT_DEPTH;
    decode_conf->qp_depth = DEFAULT_DEPTH;
    decode_conf->uu_depth = DEFAULT_DEPTH;
    decode_conf->bitenc_depth = DEFAULT_DEPTH;
    decode_conf->max_depth = DEFAULT_DEPTH;
}

void set_mime_log_config_defauts(MAIL_LogConfig* log_config)
{
    log_config->memcap = DEFAULT_MIME_MEMCAP;
    log_config->log_filename = 0;
    log_config->log_mailfrom = 0;
    log_config->log_rcptto = 0;
    log_config->log_email_hdrs = 0;
    log_config->email_hdrs_log_depth = 0;
}

bool is_decoding_enabled(DecodeConfig* decode_conf)
{
    if ( (decode_conf->b64_depth > -1) || (decode_conf->qp_depth > -1)
        || (decode_conf->uu_depth > -1) || (decode_conf->bitenc_depth > -1)
        || (decode_conf->file_depth > -1))
    {
        return true;
    }
    else
        return false;
}

bool is_mime_log_enabled(MAIL_LogConfig* log_config)
{
    if (log_config->log_email_hdrs || log_config->log_filename ||
        log_config->log_mailfrom || log_config->log_rcptto)
        return true;
    return false;
}

bool is_decoding_conf_changed(DecodeConfig* configNext, DecodeConfig* config, const
    char* preproc_name)
{
    if (configNext == NULL)
    {
        ErrorMessage("%s reload: Changing the %s configuration requires a restart.\n",
            preproc_name, preproc_name);
        return true;
    }
    if (configNext->max_mime_mem != config->max_mime_mem)
    {
        ErrorMessage("%s reload: Changing the memcap requires a restart.\n", preproc_name);

        return true;
    }
    if (configNext->b64_depth != config->b64_depth)
    {
        ErrorMessage("%s reload: Changing the b64_decode_depth requires a restart.\n",
            preproc_name);

        return true;
    }
    if (configNext->qp_depth != config->qp_depth)
    {
        ErrorMessage("%s reload: Changing the qp_decode_depth requires a restart.\n",
            preproc_name);

        return true;
    }
    if (configNext->bitenc_depth != config->bitenc_depth)
    {
        ErrorMessage("%s reload: Changing the bitenc_decode_depth requires a restart.\n",
            preproc_name);

        return true;
    }
    if (configNext->uu_depth != config->uu_depth)
    {
        ErrorMessage("%s reload: Changing the uu_decode_depth requires a restart.\n",
            preproc_name);

        return true;
    }
    if (configNext->file_depth != config->file_depth)
    {
        ErrorMessage("%s reload: Changing the file_depth requires a restart.\n", preproc_name);

        return true;
    }
    return false;
}

/*
 *
 * Purpose: Process the configuration
 *
 * Arguments: args => argument list
 *
 * Returns: -1: error or not found
 *           0: no error
 *
 */
int parse_mime_decode_args(DecodeConfig* decode_conf, char* arg, const char* preproc_name)
{
    int ret = 0;
    char errStr[ERRSTRLEN];
    int errStrLen = ERRSTRLEN;
    unsigned long value = 0;

    if ((decode_conf == NULL) || (arg == NULL))
        return 0;

    *errStr = '\0';

    if ( !strcasecmp(CONF_MAX_MIME_MEM, arg) )
    {
        ret = CheckValueInRange(get_tok(NULL, CONF_SEPARATORS), CONF_MAX_MIME_MEM,
            MIN_MIME_MEM, MAX_MIME_MEM, &value);
        decode_conf->max_mime_mem = (int)value;
    }
    else if ( !strcasecmp(CONF_B64_DECODE, arg) )
    {
        ret = ProcessDecodeDepth(decode_conf, errStr, errStrLen, CONF_B64_DECODE, DECODE_B64,
            preproc_name);
    }
    else if ( !strcasecmp(CONF_QP_DECODE, arg) )
    {
        ret = ProcessDecodeDepth(decode_conf, errStr, errStrLen, CONF_QP_DECODE, DECODE_QP,
            preproc_name);
    }
    else if ( !strcasecmp(CONF_UU_DECODE, arg) )
    {
        ret = ProcessDecodeDepth(decode_conf, errStr, errStrLen, CONF_UU_DECODE, DECODE_UU,
            preproc_name);
    }
    else if ( !strcasecmp(CONF_BITENC_DECODE, arg) )
    {
        ret = ProcessDecodeDepth(decode_conf, errStr, errStrLen, CONF_BITENC_DECODE, DECODE_BITENC,
            preproc_name);
    }
    else
    {
        return -1;
    }

    if (ret == -1)
    {
        /*
         **  Fatal Error, log error and exit.
         */
        if ( *errStr )
            ParseError("mime decode: %s", errStr);
        else
            ParseError("mime decode: %s", "undefined error");
    }

    return ret;
}

void check_decode_config(DecodeConfig* currentConfig)
{
    int max = -1;

    if (!currentConfig->max_mime_mem)
        currentConfig->max_mime_mem = DEFAULT_MAX_MIME_MEM;

    if (!currentConfig->b64_depth || !currentConfig->qp_depth
        || !currentConfig->uu_depth || !currentConfig->bitenc_depth)
    {
        currentConfig->max_depth = MAX_DEPTH;
    }
    else
    {
        if (max < currentConfig->b64_depth)
            max = currentConfig->b64_depth;

        if (max < currentConfig->qp_depth)
            max = currentConfig->qp_depth;

        if (max < currentConfig->bitenc_depth)
            max = currentConfig->bitenc_depth;

        if (max < currentConfig->uu_depth)
            max = currentConfig->uu_depth;

        currentConfig->max_depth = max;
    }
}

