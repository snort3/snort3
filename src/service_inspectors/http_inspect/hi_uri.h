/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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
 
#ifndef HI_URI_H
#define HI_URI_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
/**
**  This structure holds pointers to the different sections of an HTTP
**  request.  We need to track where whitespace begins and ends, so we
**  can evaluate the placement of the URI correctly.
**
**  For example,
**
**  GET     / HTTP/1.0
**     ^   ^          
**   start end
**
**  The end space pointers are set to NULL if there is space until the end
**  of the buffer.
*/
typedef struct s_URI_PTR
{
    const u_char *uri;                /* the beginning of the URI */
    const u_char *uri_end;            /* the end of the URI */
    const u_char *norm;               /* ptr to first normalization occurence */
    const u_char *ident;              /* ptr to beginning of the HTTP identifier */
    const u_char *first_sp_start;     /* beginning of first space delimiter */
    const u_char *first_sp_end;       /* end of first space delimiter */
    const u_char *second_sp_start;    /* beginning of second space delimiter */
    const u_char *second_sp_end;      /* end of second space delimiter */
    const u_char *param;              /* '?' (beginning of parameter field) */
    const u_char *delimiter;          /* HTTP URI delimiter (\r\n\) */
    const u_char *last_dir;           /* ptr to last dir, so we catch long dirs */
    const u_char *proxy;              /* ptr to the absolute URI */
}  URI_PTR;

#define URI_END  1
#define NO_URI  -1

#endif /* HI_URI_H */
