//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
 *
 * Description:
 *
 * This file handles normalizing SMTP traffic into the alternate buffer.
 *
 * Entry point functions:
 *
 *    SMTP_NeedNormalize()
 *    SMTP_Normalize()
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "smtp_normalize.h"

#include "protocols/packet.h"

#include "smtp.h"
#include "smtp_util.h"

/*
 * SMTP_NormalizeCmd
 *
 * If command doesn't need normalizing it will do nothing, except in
 * the case where we are already normalizing in which case the line
 * will get copied to the alt buffer.
 * If the command needs normalizing the normalized data will be copied
 * to the alt buffer.  If we are not already normalizing, all of the
 * data up to this point will be copied into the alt buffer first.
 *
 * XXX This may copy unwanted data if we are ignoring the data in the
 *     message and there was data that came before the command in the
 *     packet, for example if there are multiple transactions on the
 *     session or if we're normalizing QUIT.
 *
 * @param   p      pointer to packet structure
 * @param   ptr    pointer to beginning of command line
 * @param   eolm   start of end of line marker
 * @param   eol    end of end of line marker
 *
 * @return  response
 * @retval   0          function succeeded without error
 * @retval  -1          there were errors
 */
int SMTP_NormalizeCmd(snort::Packet* p, const uint8_t* ptr, const uint8_t* eolm, const uint8_t* eol)
{
    const uint8_t* tmp;
    const uint8_t* cmd_start;
    const uint8_t* cmd_end;
    const uint8_t* args_start;
    const uint8_t* args_end;
    const uint8_t* space = (const uint8_t*)" ";
    int need_normalize = 0;
    int ret;

    tmp = ptr;

    /* move past initial whitespace */
    while ((tmp < eolm) && isspace((int)*tmp))
        tmp++;

    /* we got whitespace before command */
    if (tmp > ptr)
        need_normalize = 1;

    /* move past the command */
    cmd_start = cmd_end = tmp;
    while ((cmd_end < eolm) && !isspace((int)*cmd_end))
        cmd_end++;

    args_start = cmd_end;
    while ((args_start < eolm) && isspace((int)*args_start))
        args_start++;

    if (args_start == eolm)
    {
        /* nothing but space after command - normalize if we got any
         * spaces since there is not an argument */
        if (args_start > cmd_end)
            need_normalize = 1;

        args_end = args_start;
    }
    else
    {
        /* more than one space between command and argument or
         * whitespace between command and argument is not a regular space character */
        if ((args_start > (cmd_end + 1)) || (*cmd_end != ' '))
            need_normalize = 1;

        /* see if there is any dangling space at end of argument */
        args_end = eolm;
        while (isspace((int)*(args_end - 1)))
            args_end--;

        if (args_end != eolm)
            need_normalize = 1;
    }

    if (need_normalize)
    {
        /* if we're not yet normalizing copy everything in the payload up to this
         * line into the alt buffer */
        if (!smtp_normalizing)
        {
            ret = SMTP_CopyToAltBuffer(p, p->data, ptr - p->data);
            if (ret == -1)
                return -1;
        }

        /* copy the command into the alt buffer */
        ret = SMTP_CopyToAltBuffer(p, cmd_start, cmd_end - cmd_start);
        if (ret == -1)
            return -1;

        /* if we actually have an argument, copy it into the alt buffer */
        if (args_start != args_end)
        {
            /* copy a 'pure' space */
            ret = SMTP_CopyToAltBuffer(p, space, 1);
            if (ret == -1)
                return -1;

            ret = SMTP_CopyToAltBuffer(p, args_start, args_end - args_start);
            if (ret == -1)
                return -1;
        }

        /* copy the end of line marker into the alt buffer */
        ret = SMTP_CopyToAltBuffer(p, eolm, eol - eolm);
        if (ret == -1)
            return -1;
    }
    else if (smtp_normalizing)
    {
        /* if we're already normalizing and didn't need to normalize this line, just
         * copy it into the alt buffer */
        ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
        if (ret == -1)
            return -1;
    }

    return 0;
}

