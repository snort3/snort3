//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// dce_smb2_utils.h author Bhargava Jandhyala <bjandhya@cisco.com>
// based on work by Todd Wease

#ifndef DCE_SMB2_UTILS_H
#define DCE_SMB2_UTILS_H

#include "dce_smb.h"
#include "dce_smb2.h"
#include "file_api/file_flows.h"
#include "sfip/sf_ip.h"

struct Smb2SidHashKey
{
    snort::SfIp cip; // client ip
    snort::SfIp sip; // server ip
    uint64_t sid;
    bool operator==(const Smb2SidHashKey& other) const
    {
        return( sid == other.sid and
               cip == other.cip and
               sip == other.sip );
    }
};

struct Smb2SidHash
{
    size_t operator()(const Smb2SidHashKey& key) const
    {
        const uint32_t* cip64 = key.cip.get_ip6_ptr();
        const uint32_t* sip64 = key.cip.get_ip6_ptr();
        const uint32_t sid_lo = key.sid & 0xFFFFFFFF;
        const uint32_t sid_hi = key.sid >> 32;
        uint32_t a, b, c;
        a = b = c = 133824503;
        a += cip64[0]; b += cip64[1]; c += cip64[2];
        mix(a, b, c);
        a += cip64[3]; b += sip64[0]; c += sip64[2];
        mix(a, b, c);
        a += sip64[3]; b += sid_lo; c += sid_hi;
        finalize(a, b, c);
        return c;
    }

private:
    inline uint32_t rot(uint32_t x, unsigned k) const
    { return (x << k) | (x >> (32 - k)); }

    inline void mix(uint32_t& a, uint32_t& b, uint32_t& c) const
    {
        a -= c; a ^= rot(c, 4); c += b;
        b -= a; b ^= rot(a, 6); a += c;
        c -= b; c ^= rot(b, 8); b += a;
        a -= c; a ^= rot(c,16); c += b;
        b -= a; b ^= rot(a,19); a += c;
        c -= b; c ^= rot(b, 4); b += a;
    }

    inline void finalize(uint32_t& a, uint32_t& b, uint32_t& c) const
    {
        c ^= b; c -= rot(b,14);
        a ^= c; a -= rot(c,11);
        b ^= a; b -= rot(a,25);
        c ^= b; c -= rot(b,16);
        a ^= c; a -= rot(c,4);
        b ^= a; b -= rot(a,14);
        c ^= b; c -= rot(b,24);
    }
};

Smb2SidHashKey get_key(uint64_t sid);

template<typename Key, typename Value, typename Hash>
class SmbSessionCache_map : public LruCacheShared<Key, Value, Hash>
{
public:
    SmbSessionCache_map() = delete;
    SmbSessionCache_map(const SmbSessionCache_map& arg) = delete;
    SmbSessionCache_map& operator=(const SmbSessionCache_map& arg) = delete;
    SmbSessionCache_map(const size_t initial_size) : LruCacheShared<Key, Value, Hash>(initial_size)
    {
    }
    virtual ~SmbSessionCache_map() { }
};

typedef SmbSessionCache_map<Smb2SidHashKey, DCE2_Smb2SessionTracker, Smb2SidHash> SmbSessionCache;

extern THREAD_LOCAL SmbSessionCache* smb2_session_cache;
extern size_t session_cache_size;

// SMB2 Session cache manipulation functions
inline void DCE2_SmbSessionCacheInit(const size_t cache_size)
{
    smb2_session_cache = new SmbSessionCache(cache_size);
}

inline DCE2_Smb2SessionTracker* DCE2_SmbSessionCacheFind(uint64_t sid)
{
    return (smb2_session_cache->find(get_key(sid))).get();
}

inline DCE2_Smb2SessionTracker* DCE2_SmbSessionCacheFindElseCreate(uint64_t sid,
    bool* entry_created)
{
    return (smb2_session_cache->find_else_create(get_key(sid), entry_created)).get();
}

inline bool DCE2_SmbSessionCacheRemove(uint64_t sid)
{
    return smb2_session_cache->remove(get_key(sid));
}

// SMB2 functions for fetching sid, tid, request type and so on.
inline uint64_t Smb2Sid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohq(&(((const Smb2SyncHdr*)hdr)->session_id));
}

inline uint32_t Smb2Tid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohl(&(((const Smb2SyncHdr*)hdr)->tree_id));
}

inline uint64_t Smb2Mid(const Smb2Hdr* hdr)
{
    return snort::alignedNtohq(&(((const Smb2SyncHdr*)hdr)->message_id));
}

inline bool Smb2Error(const Smb2Hdr* hdr)
{
    return (SMB_NT_STATUS_SEVERITY__ERROR == (uint8_t)(hdr->status >> 30));
}

inline DCE2_Smb2SessionTracker* DCE2_Smb2FindSidInSsd(DCE2_Smb2SsnData* ssd, const
    uint64_t sid)
{
    return (DCE2_Smb2SessionTracker*)(ssd->session_trackers.Find(sid));
}

inline void DCE2_Smb2InsertSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid,
    DCE2_Smb2SessionTracker* stracker)
{
    // add ssd in session tracker's tcp trackers database
    SmbFlowKey key;
    get_flow_key(&key);
    stracker->insertConnTracker(key, ssd);

    ssd->session_trackers.Insert(sid, stracker);
}

inline void DCE2_Smb2RemoveSidInSsd(DCE2_Smb2SsnData* ssd, const uint64_t sid)
{
    ssd->session_trackers.Remove(sid);
}

DCE2_Smb2TreeTracker* DCE2_Smb2InsertTid(DCE2_Smb2SsnData*, const uint32_t tid, uint8_t share_type,
    DCE2_Smb2SessionTracker*);

DCE2_Smb2SessionTracker* DCE2_Smb2FindElseCreateSid(DCE2_Smb2SsnData*, const uint64_t sid);

DCE2_Ret DCE2_Smb2InitData(DCE2_Smb2SsnData*);

void DCE2_Smb2RemoveAllSession(DCE2_Smb2SsnData* ssd);

#endif

