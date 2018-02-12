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
// flush_bucket.h author Russ Combs <rucombs@cisco.com>

#ifndef FLUSH_BUCKET_H
#define FLUSH_BUCKET_H

// FlushBuckets manage a set of flush points for stream_tcp.

#include <cstdint>
#include <vector>

class FlushBucket
{
public:
    virtual ~FlushBucket() = default;
    virtual uint16_t get_next() = 0;

    static uint16_t get_size();
    static void set(unsigned sz);
    static void clear();

protected:
    FlushBucket() = default;
};

class ConstFlushBucket : public FlushBucket
{
public:
    ConstFlushBucket(uint16_t fp)
    { pt = fp; }

    uint16_t get_next() override
    { return pt; }

private:
    uint16_t pt;
};

class VarFlushBucket : public FlushBucket
{
public:
    uint16_t get_next() override;

protected:
    VarFlushBucket() = default;
    void set_next(uint16_t);

private:
    unsigned idx = 0;
    std::vector<uint16_t> flush_points;
};

class StaticFlushBucket : public VarFlushBucket
{
public:
    StaticFlushBucket();
};

class RandomFlushBucket : public VarFlushBucket
{
public:
    RandomFlushBucket();
};

#endif

