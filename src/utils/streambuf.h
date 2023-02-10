//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef STREAMBUF
#define STREAMBUF

#include <streambuf>
#include <tuple>
#include <utility>
#include <vector>

#include "main/snort_types.h"

namespace snort
{

// an input stream over set of buffers,
// the buffer doesn't take ownership over the memory,
// no intermediate buffering between chunks
class SO_PUBLIC istreambuf_glue : public std::streambuf
{
public:
    istreambuf_glue();
    virtual ~istreambuf_glue() override = default;

    std::streamsize last_chunk_offset() const;

protected:
    // a valid s/n pair continues the chain, nullptr or zero size starts new one
    virtual std::streambuf* setbuf(char* s, std::streamsize n) override;
    virtual std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
        std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
    virtual std::streampos seekpos(std::streampos sp,
        std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
    virtual int sync() override;
    virtual std::streamsize showmanyc() override;
    virtual std::streamsize xsgetn(char* s, std::streamsize n) override;
    virtual int underflow() override;

    bool last_chunk() const
    { return cur_idx + 1 >= chunks.size(); }

    bool last_chunk(size_t idx) const
    { return idx + 1 >= chunks.size(); }

    typedef std::tuple<char*, std::streamsize, std::streamoff> Chunk;
    typedef std::vector<Chunk> Chunks;

    Chunks chunks;
    size_t cur_idx;
    std::streamsize size;
};

// an output stream over extensible array
class SO_PUBLIC ostreambuf_infl : public std::streambuf
{
public:
    static constexpr size_t size_limit = 1 << 20;

    ostreambuf_infl();
    virtual ~ostreambuf_infl() override;

    // reserve more memory for the current buffer, keeping data
    void reserve(std::streamsize n);

    // releases the current buffer,
    // the caller takes ownership over the buffer
    const char* take_data();
    const char* take_data(std::streamsize& n);

    const char* data() const
    { return pbase(); }

    std::streamsize data_len() const
    { return pptr() - pbase(); }

protected:
    virtual std::streambuf* setbuf(char* s, std::streamsize n) override;
    virtual std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way,
        std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
    virtual std::streampos seekpos(std::streampos sp,
        std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
    virtual int sync() override;
    virtual std::streamsize xsputn(const char* s, std::streamsize n) override;
    virtual std::streamsize xsgetn(char* s, std::streamsize n) override;
    virtual int overflow(int c = EOF) override;

    bool enlarge();
    bool enlarge(std::streamsize extra_len);

    struct State
    {
        const State* s;
        std::streamsize n;

        std::streamsize get_next_size()
        { auto r = n; n = s->n; s = s->s; return r; }
    };

    static const State states[];
    State gen;
};

}

#endif
