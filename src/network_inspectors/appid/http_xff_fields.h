//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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
                                                                            
// http_xff_fields.h author Sourcefire Inc.                                
 
#ifndef HTTP_XFF_FIELDS_H
#define HTTP_XFF_FIELDS_H

#include <string>

// FIXIT-L refactor
#define HTTP_XFF_FIELD_X_FORWARDED_FOR  "X-Forwarded-For"
#define HTTP_XFF_FIELD_TRUE_CLIENT_IP   "True-Client-IP"
/* #define HTTP_MAX_XFF_FIELDS             8 */
/* #define HTTP_XFF_FIELD_X_FORWARDED_FOR "" */
/* #define HTTP_XFF_FIELD_TRUE_CLIENT_IP "" */

#define HTTP_MAX_XFF_FIELDS 8

struct XffFieldValue
{
    std::string field;
    std::string value;
};


#endif
