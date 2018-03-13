//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ipv4_options.H author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_IP_OPTIONS_H
#define PROTOCOLS_IP_OPTIONS_H

#include "main/snort_types.h"

namespace snort
{
struct Packet;

namespace ip
{
struct IP4Hdr;

enum class IPOptionCodes : std::uint8_t
{
    EOL = 0x00,
    NOP = 0x01,
    RR = 0x07,
    TS = 0x44,
    SECURITY = 0x82,
    LSRR = 0x83,
    LSRR_E = 0x84,
    ESEC = 0x85,
    SATID = 0x88,
    SSRR = 0x89,
    RTRALT = 0x94,
    ANY = 0xff,
};

// FIXIT-L reduce all these classes to a simple pointer based approach
// that doesn't require any reinterpret casts (see also tcp_options.h)
struct IpOptions
{
    IPOptionCodes code;
    uint8_t len;
    uint8_t data[40];  // maximum possible

    inline uint8_t get_len() const
    { return ((uint8_t)code <= 1) ? 1 : len; }

    inline const uint8_t* get_data() const
    { return (((uint8_t)code <= 1) || (len < 2)) ? nullptr : &data[0]; }

    inline const IpOptions& next() const
    {
#ifdef __GNUC__
        //  because gcc requires strict aliasing.
        const uint8_t tmp_len = ((uint8_t)code <= 1) ? 1 : len;
        const uint8_t* const tmp = reinterpret_cast<const uint8_t*>(this);
        const IpOptions* opt = reinterpret_cast<const IpOptions*>(&tmp[tmp_len]);
        return *opt;

#else
        // ... and the legible code
        if ( (uint8_t)code <= 1 )
            return reinterpret_cast<const IpOptions&>(len);
        else
            return reinterpret_cast<const IpOptions&>(data[len -2]);
#endif
    }
};

/*
 * really creative name ... right
 * Use IpOptionIter ... this is the placeholder
 */
class SO_PUBLIC IpOptionIteratorIter
{
public:
    IpOptionIteratorIter(const IpOptions*);

    bool operator==(const IpOptionIteratorIter& rhs)
    { return opt == rhs.opt; }

    bool operator!=(const IpOptionIteratorIter& rhs)
    { return opt != rhs.opt; }

    // I'd suggest just using IpOptionIterator and completely ignoring this
    // horror of a ++ operation.
    IpOptionIteratorIter& operator++()
    {
        opt = &opt->next();
        return *this;
    }

    const IpOptions& operator*() const;

private:
    const IpOptions* opt;
};

/*
 * really creative name ... right
 * Use IP ranged for loop rather than calling this directly.
 * i.e.,
 *      IpOptionIter iter(ip4h, p)
 *      for (auto i : iter)
 *      {
 *          do_something
 *      }
 */
class SO_PUBLIC IpOptionIterator
{
public:
    // CONSTRUCTOR VALID AFTER DECODE()
    // Some options in the provided header may not be valid.
    // Provide the packet struct ensures only valid options
    // will be returned
    IpOptionIterator(const IP4Hdr* const, const Packet* const);

    // If you already know the validated option length (for instance,
    // if you are in a decode() method), then call this constructor.
    // You MUST validate all ip_options within len before using this
    // constructor
    IpOptionIterator(const IP4Hdr* const, const uint8_t valid_hdr_len);
    IpOptionIteratorIter begin() const;
    IpOptionIteratorIter end() const;

private:
    const uint8_t* end_ptr;
    const uint8_t* start_ptr;
};
} // namespace ip
} // namespace snort
#endif

