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

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      NHttpSplitter class and subclasses declarations
//

#ifndef NHTTP_SPLITTER_H
#define NHTTP_SPLITTER_H

#include "nhttp_enum.h"

//-------------------------------------------------------------------------
// NHttpSplitter class
//-------------------------------------------------------------------------

class NHttpSplitter {
public:
    virtual void reset() { octets_seen = 0; num_crlf = 0; num_flush = 0; };
    virtual NHttpEnums::SectionType split(const uint8_t* buffer, uint32_t length) = 0;
    virtual ~NHttpSplitter() = default;
    uint32_t get_num_flush() { return num_flush; };
    uint32_t get_octets_seen() { return octets_seen; };

protected:
    uint32_t octets_seen = 0;
    uint32_t num_crlf = 0;
    uint32_t num_flush = 0;
};

class NHttpStartSplitter : public NHttpSplitter {
public:
    NHttpEnums::SectionType split(const uint8_t* buffer, uint32_t length);
};

class NHttpHeaderSplitter : public NHttpSplitter {
public:
    NHttpEnums::SectionType split(const uint8_t* buffer, uint32_t length);
};

#endif

