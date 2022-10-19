//--------------------------------------------------------------------------
// Copyright (C) 2018-2022 Cisco and/or its affiliates. All rights reserved.
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
// mpse_batch.h author Titan IC Systems <support@titan-ic.com>

#ifndef MPSE_BATCH_H
#define MPSE_BATCH_H

#include <unordered_map>
#include <vector>

#include "framework/mpse.h"
#include "main/snort_types.h"

namespace snort
{
class SO_PUBLIC MpseGroup
{
public:
    MpseGroup()
    { normal_mpse = nullptr; offload_mpse = nullptr; }

    MpseGroup(Mpse* normal)
    { normal_mpse = normal; offload_mpse = nullptr; }

    ~MpseGroup();

    Mpse* get_normal_mpse() const
    { return normal_mpse; }

    // Offload will only be actioned if the offload_search_api is configured.
    // If the offload_search_api is the same as the normal_search_api then
    // only the normal mpse will get created and thus if the offload mpse
    // is requested the normal mpse will be returned otherwise the offload_mpse
    // will get returned
    Mpse* get_offload_mpse() const
    { return offload_mpse ? offload_mpse : normal_mpse; }

    bool create_normal_mpse(const SnortConfig*, const MpseAgent* agent);
    bool create_normal_mpse(const SnortConfig*, const char*);

    bool create_offload_mpse(const SnortConfig*, const MpseAgent* agent);
    bool create_offload_mpse(const SnortConfig*);

    inline bool can_fallback() const
    { return get_offload_mpse() != normal_mpse; }

public:  // FIXIT-L privatize
    Mpse* normal_mpse;
    Mpse* offload_mpse;
    bool normal_is_dup = false;
    bool offload_is_dup = false;
};

template<typename BUF = const uint8_t*, typename LEN = unsigned>
struct MpseBatchKey
{
    BUF buf;
    LEN len;
    MpseBatchKey(BUF b, LEN n)
    {
        this->buf = b;
        this->len = n;
    }

    bool operator==(const MpseBatchKey &k) const
    {
        return buf == k.buf && len == k.len;
    }
};

struct MpseBatchKeyHash
{
    template <class BUF, class LEN>
    std::size_t operator()(const MpseBatchKey<BUF, LEN> &k) const
    {
        std::size_t h1 = std::hash<BUF>()(k.buf);
        std::size_t h2 = std::hash<LEN>()(k.len);

        return h1 ^ h2;
    }
};

class MpseBatchItem
{
public:
    std::vector<MpseGroup*> so;
    bool done;
    bool error;
    int matches;

    MpseBatchItem(MpseGroup* s = nullptr)
    { if (s) so.push_back(s); done = false; error = false; matches = 0; }
};

struct MpseBatch
{
    MpseMatch mf;
    void* context;
    std::unordered_map<MpseBatchKey<>, MpseBatchItem, MpseBatchKeyHash> items;

    void search();
    Mpse::MpseRespType receive_responses();

    void offload_search();
    Mpse::MpseRespType receive_offload_responses();

    bool search_sync();
    bool can_fallback() const;

    static Mpse::MpseRespType poll_responses(MpseBatch*& batch)
    { return Mpse::poll_responses(batch, snort::Mpse::MPSE_TYPE_NORMAL); }

    static Mpse::MpseRespType poll_offload_responses(MpseBatch*& batch)
    { return Mpse::poll_responses(batch, snort::Mpse::MPSE_TYPE_OFFLOAD); }

};

inline void MpseBatch::search()
{
    items.begin()->second.so[0]->get_normal_mpse()->search(*this, Mpse::MPSE_TYPE_NORMAL);
}

inline Mpse::MpseRespType MpseBatch::receive_responses()
{
    return items.begin()->second.so[0]->get_normal_mpse()->
        receive_responses(*this, Mpse::MPSE_TYPE_NORMAL);
}

inline void MpseBatch::offload_search()
{
    assert(items.begin()->second.so[0]->get_offload_mpse());

    items.begin()->second.so[0]->get_offload_mpse()->
        search(*this, Mpse::MPSE_TYPE_OFFLOAD);
}

inline Mpse::MpseRespType MpseBatch::receive_offload_responses()
{
    assert(items.begin()->second.so[0]->get_offload_mpse());

    return items.begin()->second.so[0]->get_offload_mpse()->
        receive_responses(*this, Mpse::MPSE_TYPE_OFFLOAD);
}

inline bool MpseBatch::can_fallback() const
{
    return items.begin()->second.so[0]->can_fallback();
}
}

#endif

