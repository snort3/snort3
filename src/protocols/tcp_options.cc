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
// tcp_options.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_options.h"

#include "packet.h"
#include "tcp.h"

namespace snort
{
namespace tcp
{
TcpOptIteratorIter::TcpOptIteratorIter(const TcpOption* first_opt) : opt(first_opt) { }

const TcpOption& TcpOptIteratorIter::operator*() const { return *opt; }

TcpOptIterator::TcpOptIterator(const TCPHdr* const tcp_header, const Packet* const p)
{
    const uint8_t* const hdr = (const uint8_t*)tcp_header;
    start_ptr = hdr + TCP_MIN_HEADER_LEN;
    end_ptr = start_ptr; // == begin()

    for (int i = p->num_layers-1; i >= 0; --i)
    {
        if (p->layers[i].start == (const uint8_t*)tcp_header)
        {
            // Can't use the tph_header->hlen() because the entire may
            // be an EOF or invalid options. However, this layers length
            // has been valid by the codecs.
            end_ptr = (hdr + p->layers[i].length);
            return;
        }
    }

    // Can occur if tcp_layer > max_layers.  No Options in such a case.
}

TcpOptIterator::TcpOptIterator(const TCPHdr* const tcp_header, const uint32_t valid_hdr_len)
{
    const uint8_t* const hdr = (const uint8_t*)tcp_header;
    start_ptr = hdr + TCP_MIN_HEADER_LEN;

    if (valid_hdr_len < TCP_MIN_HEADER_LEN)
        end_ptr = start_ptr;
    else
        end_ptr = hdr + valid_hdr_len;
}

TcpOptIteratorIter TcpOptIterator::begin() const
{
    return TcpOptIteratorIter(reinterpret_cast<const TcpOption*>(start_ptr));
}

TcpOptIteratorIter TcpOptIterator::end() const
{
    return TcpOptIteratorIter(reinterpret_cast<const TcpOption*>(end_ptr));
}
} // namespace ip
} // namespace snort

