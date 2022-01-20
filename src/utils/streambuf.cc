//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "streambuf.h"

#include <cassert>
#include <cstring>

using namespace snort;
using namespace std;

#define max(x, y) std::max((streamsize)(x), (streamsize)(y))
#define min(x, y) std::min((streamsize)(x), (streamsize)(y))

istreambuf_glue::istreambuf_glue() :
    streambuf(),
    chunks(),
    cur_idx(0),
    size(0)
{

}

streamsize istreambuf_glue::last_chunk_offset() const
{
    if (chunks.empty())
        return 0;

    return get<2>(chunks.back());
}

// cppcheck-suppress unusedFunction
streambuf* istreambuf_glue::setbuf(char* s, streamsize n)
{
    n = max(0, n);

    if (!s || !n)
    {
        chunks.clear();
        cur_idx = 0;
        size = 0;
        return this;
    }

    if (!size)
        setg(s, s, s + n);

    chunks.emplace_back(Chunk(s, n, size));
    size += n;

    return this;
}

// cppcheck-suppress unusedFunction
streampos istreambuf_glue::seekoff(streamoff off, ios_base::seekdir way, ios_base::openmode which)
{
    if (!(which & ios_base::in))
        return -1;

    if (chunks.empty())
        return -1;

    auto& c_chunk = chunks[cur_idx];
    auto c_chunk_off = get<2>(c_chunk);
    auto c_off = c_chunk_off + gptr() - eback();

    streampos pos;

    switch (way)
    {
    case ios_base::beg: pos = 0;     break;
    case ios_base::cur: pos = c_off; break;
    case ios_base::end: pos = size;  break;
    default:
        return -1;
    }

    pos += off;
    pos = max(0, pos);
    pos = min(pos, size);

    size_t i = 0;
    for (auto chunk : chunks)
    {
        auto ptr = get<0>(chunk);
        auto len = get<1>(chunk);
        auto b_off = get<2>(chunk);
        auto e_off = b_off + len;

        if (b_off <= pos &&
            (pos < e_off || (pos == e_off && last_chunk(i))))
        {
            setg(ptr, ptr - b_off + pos, ptr + len);
            cur_idx = i;
            break;
        }

        i += 1;
    }

    return pos;
}

// cppcheck-suppress unusedFunction
streampos istreambuf_glue::seekpos(streampos pos, ios_base::openmode which)
{
    if (!(which & ios_base::in))
        return -1;

    if (chunks.empty())
        return -1;

    pos = max(0, pos);
    pos = min(pos, size);

    int i = 0;
    for (auto chunk : chunks)
    {
        auto ptr = get<0>(chunk);
        auto len = get<1>(chunk);
        auto b_off = get<2>(chunk);
        auto e_off = b_off + len;

        if (b_off <= pos && pos < e_off)
        {
            auto off = pos - b_off;
            setg(ptr, ptr + off, ptr + len);
            cur_idx = i;
            break;
        }

        i += 1;
    }

    return pos;
}

int istreambuf_glue::sync()
{
    return -1;
}

// cppcheck-suppress unusedFunction
streamsize istreambuf_glue::showmanyc()
{
    if (chunks.empty())
        return -1;

    auto& chunk = chunks[cur_idx];
    auto chunk_off = get<2>(chunk);
    auto off = chunk_off + gptr() - eback();

    return size - off;
}

// cppcheck-suppress unusedFunction
streamsize istreambuf_glue::xsgetn(char* s, streamsize n)
{
    assert(n >= 0);

    if (chunks.empty())
        return -1;

    streamsize r = 0;

    while (true)
    {
        streamsize l = min(egptr() - gptr(), n);
        memcpy(s, gptr(), l);
        gbump(l);

        s += l;
        r += l;
        n -= l;

        if (n <= 0 || last_chunk())
            break;

        cur_idx += 1;

        auto& chunk = chunks[cur_idx];
        auto ptr = get<0>(chunk);
        auto len = get<1>(chunk);

        setg(ptr, ptr, ptr + len);
    }

    return r;
}

// cppcheck-suppress unusedFunction
int istreambuf_glue::underflow()
{
    if (chunks.empty())
        return traits_type::eof();

    if (last_chunk())
        return traits_type::eof();

    cur_idx += 1;

    auto& chunk = chunks[cur_idx];
    auto ptr = get<0>(chunk);
    auto len = get<1>(chunk);

    setg(ptr, ptr, ptr + len);

    return sgetc();
}

const ostreambuf_infl::State ostreambuf_infl::states[] =
{
    {states + 1, 1 << 11},
    {states + 2, 1 << 12},
    {states + 3, 1 << 13},
    {states + 4, 1 << 14},
    {states + 4, 1 << 15}
};

ostreambuf_infl::ostreambuf_infl() :
    streambuf(),
    gen(states[0])
{

}

ostreambuf_infl::~ostreambuf_infl()
{
    delete[] pbase();
}

void ostreambuf_infl::reserve(streamsize n)
{
    auto base = pbase();
    auto eptr = epptr();
    auto size = eptr - base;

    if (n > size)
        enlarge(n - size);
}

const char* ostreambuf_infl::take_data()
{
    auto data = pbase();

    setp(nullptr, nullptr);

    gen.s = states[0].s;
    gen.n = states[0].n;

    return data;
}

const char* ostreambuf_infl::take_data(streamsize& n)
{
    auto data = pbase();

    n = pptr() - data;
    setp(nullptr, nullptr);

    gen.s = states[0].s;
    gen.n = states[0].n;

    return data;
}

streambuf* ostreambuf_infl::setbuf(char* s, streamsize n)
{
    n = min(n, size_limit);

    delete[] pbase();
    setp(s, s + max(0, n));
    return this;
}

streampos ostreambuf_infl::seekoff(streamoff off, ios_base::seekdir way, ios_base::openmode which)
{
    if (!(which & ios_base::out))
        return -1;

    if (off == 0 && way == ios_base::cur)
        return pptr() - pbase();

    auto base = pbase();
    auto ptr = pptr();
    auto eptr = epptr();
    auto size = eptr - base;

    streampos cpos = ptr - base;
    streampos npos;

    switch (way)
    {
    case ios_base::beg: npos = 0;           break;
    case ios_base::cur: npos = ptr - base;  break;
    case ios_base::end: npos = eptr - base; break;
    default:
        return -1;
    }

    npos += off;
    npos = max(0, npos);
    npos = min(npos, size);

    pbump(npos - cpos);

    return npos;
}

streampos ostreambuf_infl::seekpos(streampos pos, ios_base::openmode which)
{
    if (!(which & ios_base::out))
        return -1;

    auto base = pbase();
    auto ptr = pptr();
    auto eptr = epptr();
    auto size = eptr - base;

    pos = max(0, pos);
    pos = min(pos, size);

    streampos cpos = ptr - base;
    pbump(pos - cpos);

    return pos;
}

int ostreambuf_infl::sync()
{
    return -1;
}

// cppcheck-suppress unusedFunction
streamsize ostreambuf_infl::xsputn(const char* s, streamsize n)
{
    assert(n >= 0);
    n = max(0, n);

    auto c_avail = epptr() - pptr();
    if (n > c_avail)
        gen.n > (n - c_avail) ? enlarge() : enlarge(n - c_avail);

    auto n_avail = epptr() - pptr();
    n = min(n, n_avail);

    memcpy(pptr(), s, n);
    pbump(n);

    return n;
}

// cppcheck-suppress unusedFunction
int ostreambuf_infl::overflow(int c)
{
    if (traits_type::eof() == c)
        return traits_type::eof();

    if (!enlarge())
        return traits_type::eof();

    *pptr() = c;
    pbump(1);

    return c;
}

bool ostreambuf_infl::enlarge()
{
    return enlarge(gen.get_next_size());
}

bool ostreambuf_infl::enlarge(streamsize extra_len)
{
    assert(extra_len > 0);

    auto c_pbase = pbase();
    auto c_pptr = pptr();
    auto c_epptr = epptr();
    auto c_size = c_epptr - c_pbase;

    auto n_size = c_size + extra_len;
    n_size = min(n_size, size_limit);

    auto n_off = c_pptr - c_pbase;
    auto n_pbase = new char[n_size];
    auto n_epptr = n_pbase ? n_pbase + n_size : nullptr;

    assert(c_pptr >= c_pbase);

    if (c_pbase && n_pbase)
        memcpy(n_pbase, c_pbase, c_size);

    delete[] c_pbase;
    setp(n_pbase, n_epptr);
    pbump(n_off);

    return n_pbase != nullptr && n_epptr > n_pbase;
}
