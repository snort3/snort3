//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_segment.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Sep 21, 2015

#include "flow/flow_control.h"
#include "perf_monitor/perf.h"
#include "protocols/packet.h"
#include "tcp_module.h"
#include "tcp_segment.h"

THREAD_LOCAL Memcap* tcp_memcap = nullptr;

TcpSegment::TcpSegment() :
    prev( nullptr ), next( nullptr ), tv( { 0, 0 } ), ts( 0 ), seq( 0 ), orig_dsize( 0 ),
    payload_size( 0 ), urg_offset( 0 ), buffered( false ), data(nullptr), payload( nullptr )
{

}

TcpSegment::~TcpSegment()
{
    // TODO Auto-generated destructor stub
}

//-------------------------------------------------------------------------
// TcpSegment stuff
//-------------------------------------------------------------------------

TcpSegment* TcpSegment::init( const struct timeval& tv, const uint8_t* data, unsigned dsize)
{
    TcpSegment* ss;

    tcp_memcap->alloc( dsize );
    ss = new TcpSegment;
    if( !ss )
    {
        tcp_memcap->dealloc( dsize );
        return nullptr;
    }

    ss->data = ( uint8_t * ) malloc( dsize );
    ss->payload = ss->data;
    ss->tv = tv;
    memcpy(ss->payload, data, dsize);
    ss->orig_dsize = dsize;
    ss->payload_size = ss->orig_dsize;

    return ss;
}

void TcpSegment::term( void )
{
    tcp_memcap->dealloc( orig_dsize );
    free( data );
    tcpStats.segs_released++;
    delete this;
}

bool TcpSegment::is_retransmit( const uint8_t* rdata, uint16_t rsize, uint32_t rseq )
{
    // retransmit must have same payload at same place
    if( !SEQ_EQ( seq, rseq ) )
        return false;

    if( ( ( payload_size <= rsize ) and !memcmp( data, rdata, payload_size ) )
            or ( ( payload_size > rsize ) and !memcmp( data, rdata, rsize ) ) )
        return true;

    return false;
}
