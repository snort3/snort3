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
// mpse.h author Russ Combs <rucombs@cisco.com>

#ifndef MPSE_H
#define MPSE_H

#include <string>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "thread.h"
#include "framework/base_api.h"
#include "time/profiler.h"

/*
*   Move these defines to a generic Win32/Unix compatability file,
*   there must be one somewhere...
*/
#ifndef CDECL
#define CDECL
#endif

// this is the current version of the api
#define SEAPI_VERSION 0

// this is the version of the api the plugins are using
// to be useful, these must be explicit (*_V0, *_V1, ...)
#define SEAPI_PLUGIN_V0 0

struct SnortConfig;
struct MpseApi;

typedef int (*mpse_build_f)(SnortConfig*, void *id, void **existing_tree);
typedef int (*mpse_negate_f)(void *id, void **list);
typedef int (*mpse_action_f)(void* id, void* tree, int index, void *data, void *neg_list);

class Mpse
{
public:
    static Mpse* instantiate(
        SnortConfig* sc,
        const char* method, bool use_global_counter_flag,
        void (*userfree)(void *p),
        void (*optiontreefree)(void **p),
        void (*neg_list_free)(void **p));

    static uint64_t get_pattern_byte_count();
    static void reset_pattern_byte_count();

    static int print_summary(SnortConfig*, const char* method);
    static void init_summary();
    static void print_qinfo();

public:
    virtual ~Mpse() { };

    virtual int add_pattern(
        SnortConfig* sc, void* P, int m,
        unsigned noCase, unsigned offset, unsigned depth,
        unsigned negative, void* ID, int IID ) = 0;

    virtual int prep_patterns(
        SnortConfig*, mpse_build_f, mpse_negate_f) = 0;

    int search(
        const unsigned char* T, int n, mpse_action_f,
        void* data, int* current_state );

    virtual void set_opt(int) { };
    virtual int print_info() { return 0; };
    virtual int get_pattern_count() { return 0; };

    const char* get_method() { return method.c_str(); };
    void set_verbose(bool b = true) { verbose = b; };

    void set_api(const MpseApi* p) { api = p; };
    const MpseApi* get_api() { return api; };

protected:
    Mpse(const char* method, bool use_gc);

    virtual int _search(
        const unsigned char* T, int n, mpse_action_f,
        void* data, int* current_state ) = 0;

private:
    std::string method;
    bool inc_global_counter;
    int verbose;
    const MpseApi* api;
};

#ifdef PERF_PROFILING
extern THREAD_LOCAL PreprocStats mpsePerfStats;
#endif

typedef void (*mpse_opt_f)(SnortConfig*);
typedef void (*mpse_exe_f)();

typedef Mpse* (*mpse_new_f)(
    SnortConfig* sc,
    class Module*,
    bool use_gc,
    void (*user_free)(void*),
    void (*tree_free)(void**),
    void (*list_free)(void**));

typedef void (*mpse_del_f)(Mpse*);

struct MpseApi
{
    BaseApi base;
    bool trim;

    mpse_opt_f activate;
    mpse_opt_f setup;
    mpse_exe_f start;
    mpse_exe_f stop;
    mpse_new_f ctor;
    mpse_del_f dtor;
    mpse_exe_f init;
    mpse_exe_f print;
};

#endif

