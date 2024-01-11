//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// geneve.h author Raman S. Krishnan <ramanks@cisco.com>

#ifndef PROTOCOLS_GENEVE_H
#define PROTOCOLS_GENEVE_H

namespace snort
{
namespace geneve
{

// The max size of the data portion of the option (((2 ^ 5) - 1) * 4).
#define MAX_OPT_DATA_LEN 124

// Geneve Variable-Length Option (from RFC8926):
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Option Class         |      Type     |R|R|R| Length  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   ~                  Variable-Length Option Data                  ~
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
struct GeneveOpt
{
    uint16_t g_class;
    uint8_t  g_type;
    uint8_t  g_len;

    uint16_t optclass() const
    { return (ntohs(g_class)); }

    bool is_set(uint16_t which) const
    { return (g_type & which); }

    uint8_t type() const
    { return (g_type); }

    // Size of GeneveOpt header plus the variable-length data for this option.
    uint8_t olen() const
    { return (sizeof(GeneveOpt) + ((g_len & 0x1f) * 4)); }

    // Size of the variable-length data section for this option.
    uint8_t data_len() const
    { return ((g_len & 0x1f) * 4); }
};

struct GeneveOptData
{
    GeneveOptData(const GeneveOpt* g_opt, const uint8_t* opt_data, uint8_t len)
    {
        assert(len <= MAX_OPT_DATA_LEN);
        opt = *g_opt;
        memcpy(data, opt_data, len);
    }

    GeneveOpt opt;
    uint8_t data[MAX_OPT_DATA_LEN];
};

// Geneve Header (from RFC8926):
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        Virtual Network Identifier (VNI)       |    Reserved   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   ~                    Variable-Length Options                    ~
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
struct GeneveHdr
{
    uint8_t g_vl;
    uint8_t g_flags;
    uint16_t g_proto;
    uint8_t g_vni[ 3 ];
    uint8_t g_rsvd;

    // Size of header fields plus the variable-length option section.
    uint16_t hlen() const
    { return (sizeof(GeneveHdr) + ((g_vl & 0x3f) * 4)); }

    uint8_t version() const
    { return (g_vl >> 6); }

    // Size of the variable-length option section.
    uint8_t opts_len() const
    { return ((g_vl & 0x3f) * 4); }

    bool is_set(uint16_t which) const
    { return (g_flags & which); }

    uint16_t proto() const
    { return (ntohs(g_proto)); }

    uint32_t vni() const
    { return ((g_vni[0] << 16) | (g_vni[1] << 8) | g_vni[2]); }
};

struct GeneveLyr
{
    GeneveHdr hdr;      // Must be first in structure.
    uint8_t data[256];  // Max size of variable options.

    std::vector<GeneveOptData> get_opt_data() const
    {
        std::vector<GeneveOptData> options;
        const uint16_t all_opt_len = hdr.opts_len();
        uint16_t offset = 0;
        const uint8_t* dptr = data;

        while (offset < all_opt_len)
        {
            const GeneveOpt* const opt = reinterpret_cast<const GeneveOpt*>(dptr);
            const uint8_t olen = opt->olen();

            if ((offset + olen) > all_opt_len)
                break;  // Invalid opt length.

            options.emplace_back(opt, dptr + sizeof(GeneveOpt), opt->data_len());

            dptr += olen;
            offset += olen;
        }

        return options;
    }
} __attribute__((packed));

} // namespace geneve
} // namespace snort

#endif
