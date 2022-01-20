//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// file_oleheader.cc author Amarnath Nayak amarnaya@cisco.com

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_oleheader.h"

unsigned char hdr_sig[8] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

bool OleHeader::set_byte_order(const uint8_t* buf)
{
    byte_order = buf[0]<< 8 | buf[1];
    if (byte_order == 0XFEFF)
        byte_order_endian = LITL_END;

    else if (byte_order == 0XFFFE)
        byte_order_endian = BIG_END;

    else
        return false;

    return true;
}

byte_order_endianess OleHeader::get_byte_order()
{
    return byte_order_endian;
}

bool OleHeader::match_ole_sig(const uint8_t* buf)
{
    memcpy(sig ,(const char*)buf, 8);

    if (memcmp(sig, hdr_sig, 8) == 0)
        return true;
    else
        return false;
}

void OleHeader::set_minor_version(const uint8_t* buf)
{
    minor_version = (!byte_order_endian) ? LETOHS_UNALIGNED(buf) : BETOHS_UNALIGNED(buf);
}

uint16_t OleHeader::get_minor_version()
{
    return minor_version;
}

void OleHeader::set_major_version(const uint8_t* buf)
{
    major_version = (!byte_order_endian) ? LETOHS_UNALIGNED(buf) : BETOHS_UNALIGNED(buf);
}

uint16_t OleHeader::get_major_version()
{
    return major_version;
}

void OleHeader::set_sector_size(const uint8_t* buf)
{
    sector_size = (!byte_order_endian) ? exp2(LETOHS_UNALIGNED(buf)) : exp2(BETOHS_UNALIGNED(buf));
}

uint16_t OleHeader::get_sector_size()
{
    return sector_size;
}

void OleHeader::set_mini_sector_size(const uint8_t* buf)
{
    mini_sector_size = (!byte_order_endian) ? exp2(LETOHS_UNALIGNED(buf)) : exp2(BETOHS_UNALIGNED(
        buf));
}

uint16_t OleHeader::get_mini_sector_size()
{
    return mini_sector_size;
}

void OleHeader::set_dir_sector_count(const uint8_t* buf)
{
    dir_sector_count = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_dir_sector_count()
{
    return dir_sector_count;
}

void OleHeader::set_first_dir(const uint8_t* buf)
{
    first_dir = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_first_dir()
{
    return first_dir;
}

void OleHeader::set_difat_count(const uint8_t* buf)
{
    difat_count = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_difat_count()
{
    return difat_count;
}

void OleHeader::set_fat_sector_count(const uint8_t* buf)
{
    fat_sector_count = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_fat_sector_count()
{
    return fat_sector_count;
}

void OleHeader::set_minifat_cutoff(const uint8_t* buf)
{
    minifat_cutoff = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

uint32_t OleHeader::get_minifat_cutoff()
{
    return minifat_cutoff;
}

void OleHeader::set_first_minifat(const uint8_t* buf)
{
    first_minifat = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_first_minifat()
{
    return first_minifat;
}

void OleHeader::set_minifat_count(const uint8_t* buf)
{
    minifat_count = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_minifat_count()
{
    return minifat_count;
}

void OleHeader::set_first_difat(const uint8_t* buf)
{
    first_difat = (!byte_order_endian) ? LETOHL_UNALIGNED(buf) : BETOHL_UNALIGNED(buf);
}

int32_t OleHeader::get_first_difat()
{
    return first_difat;
}

void OleHeader::set_difat_array(const uint8_t* buf)
{
    for (int i = 0; i < MAX_DIFAT_SECTORS; i++)
    {
        difat_array[i] = (!byte_order_endian) ? LETOHL_UNALIGNED(buf + (i * 4)) :
            BETOHL_UNALIGNED(buf + (i * 4));
    }
}

int32_t OleHeader::get_difat_array(int num)
{
    return difat_array[num];
}

