
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tp_appid_module_api.h"
#include "managers/module_manager.h"
#include "appid_module.h"
#include "tp_lib_handler.h"


static void* tp_appid_profiler_malloc(size_t size)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    return operator new(size);
}

static void tp_appid_profiler_free(void* p)
{
    // cppcheck-suppress unreadVariable
    snort::Profile profile(tp_appid_perf_stats);
    if (p)
        operator delete(p);
}

TPAppidProfilerFunctions get_tp_appid_profiler_functions()
{
    return {tp_appid_profiler_malloc,tp_appid_profiler_free};
}
