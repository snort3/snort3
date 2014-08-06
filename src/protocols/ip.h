/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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

// ip.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* !WIN32 */
#include <netinet/in_systm.h>
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif /* !IFNAMSIZ */
#endif /* !WIN32 */

#include <cstring>

#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "sfip/sfip_t.h"

#ifndef IP_H
#define IP_H

class Packet;

namespace ip
{

// keeping this as a class to avoid confusion.
class IpApi
{
public:
//    IpApi();   constructor and destructor MUST remain a trivial. Adding
//    ~IpApi();  any non-trivial code will cause a compilation failure.

    void set(const IPHdr* h4);
    void set(const ipv6::IP6RawHdr* h6);
    bool set(const uint8_t* raw_ip_data);
    void reset();
    const sfip_t* get_src();
    const sfip_t* get_dst();
    uint32_t id(const Packet* const p);
    uint16_t off(const Packet* const p);


    inline uint16_t tos()
    { return ip4h ? ip4h->get_tos() : ip6h ? ip6h->get_tos() : 0; }

    inline uint8_t ttl()
    { return ip4h ? ip4h->get_ttl() : ip6h ? ip6h->get_hop_lim() : 0; }

    inline uint8_t proto()
    { return ip4h ? ip4h->get_proto() : ip6h ? ip6h->get_next() : 0; }

    inline uint16_t len()
    { return ip4h ? ip4h->get_len() : ip6h ? ip6h->get_len() : 0; }

    inline uint8_t hlen()
    { return ip4h ? ip4h->get_hlen() : ip6h ? ip6h->get_hlen() : 0; }

    inline uint8_t ver()
    { return ip4h ? ip4h->get_ver() : ip6h ? ip6h->get_ver() : 0; }


private:
    sfip_t src;
    sfip_t dst;
    const sfip_t* src_p;
    const sfip_t* dst_p;
    const IPHdr* ip4h;
    const ipv6::IP6RawHdr* ip6h;
};

} // namespace ip

#endif
