/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifndef GTP_H
#define GTP_H

namespace gtp{

namespace detail{
const uint32_t GTP_MIN_LEN = 8;
const uint32_t GTP_V0_HEADER_LEN = 20;
const uint32_t GTP_V1_HEADER_LEN = 12;



} // namespace detail


/* GTP basic Header  */
struct GTPHdr
{
    uint8_t  flag;              /* flag: version (bit 6-8), PT (5), E (3), S (2), PN (1) */
    uint8_t  type;              /* message type */
    uint16_t length;            /* length */

};

inline uint32_t min_hdr_len()
{
    return detail::GTP_MIN_LEN;
}

inline uint32_t v0_hdr_len()
{
    return detail::GTP_V0_HEADER_LEN;
}

inline uint32_t v1_hdr_len()
{
    return detail::GTP_V1_HEADER_LEN;
}

} // namespace gtp

// typedefed values which should be removed at some point
typedef gtp::GTPHdr GTPHdr;

#endif
