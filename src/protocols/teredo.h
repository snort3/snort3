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


#ifndef PROTOCOLS_TEREDO_H
#define PROTOCOLS_TEREDO_H

#include <cstdint>



namespace teredo
{

namespace detail
{

const uint32_t TEREDO_PORT = 3544;
const uint32_t TEREDO_INDICATOR_ORIGIN = 0x00;
const uint32_t TEREDO_INDICATOR_ORIGIN_LEN = 8;
const uint32_t TEREDO_INDICATOR_AUTH = 0x01;
const uint32_t TEREDO_INDICATOR_AUTH_MIN_LEN = 13;
const uint32_t TEREDO_MIN_LEN = 2;


} // namespace detail



inline bool is_teredo_port(uint16_t port)
{
    return port == (detail::TEREDO_PORT);
}

inline uint32_t min_hdr_len()
{
    return detail::TEREDO_MIN_LEN;
}

inline uint32_t indicator_origin()
{
    return detail::TEREDO_INDICATOR_ORIGIN;
}

inline uint32_t indicator_origin_len()
{
    return detail::TEREDO_INDICATOR_ORIGIN_LEN;
}

inline uint32_t inidicator_auth()
{
    return detail::TEREDO_INDICATOR_AUTH;
}

inline uint32_t min_indicator_auth_len()
{
    return detail::TEREDO_INDICATOR_AUTH_MIN_LEN;
}

} // namespace teredo

#endif
