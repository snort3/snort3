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
// ipv4_options.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ipv4_options.h"

#include "packet.h"

namespace snort
{
namespace ip
{
IpOptionIteratorIter::IpOptionIteratorIter(const IpOptions* first_opt) : opt(first_opt)
{ }

const IpOptions& IpOptionIteratorIter::operator*() const
{ return *opt; }

IpOptionIterator::IpOptionIterator(const IP4Hdr* const ip4_header, const Packet* const p)
{
    const uint8_t* const hdr = (const uint8_t*)ip4_header;
    start_ptr = hdr + IP4_HEADER_LEN;
    end_ptr = start_ptr;

    for (int i = p->num_layers-1; i >= 0; --i)
    {
        if (p->layers[i].start == (const uint8_t*)ip4_header)
        {
            // the Options do not necessarily include
            // the entire header
            end_ptr = (hdr + p->layers[i].length);
            return;
        }
    }

    // Can occur if tcp_layer > max_layers.  No Options in such a case.
}

IpOptionIterator::IpOptionIterator(const IP4Hdr* const ip4_header, const uint8_t valid_hdr_len)
{
    const uint8_t* const hdr = (const uint8_t*)ip4_header;
    start_ptr = hdr + IP4_HEADER_LEN;

    if (valid_hdr_len < IP4_HEADER_LEN)
        end_ptr = start_ptr;
    else
        end_ptr = hdr + valid_hdr_len;
}

IpOptionIteratorIter IpOptionIterator::begin() const
{
    return IpOptionIteratorIter(reinterpret_cast<const IpOptions*>(start_ptr));
}

IpOptionIteratorIter IpOptionIterator::end() const
{
    return IpOptionIteratorIter(reinterpret_cast<const IpOptions*>(end_ptr));
}
} // namespace ip
} // namespace snort

