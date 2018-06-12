#ifndef LOG_MESSGE_MOCK
#define LOG_MESSAGE_MOCK

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdarg>

using namespace std;

namespace snort
{
// Note: without SO_PUBLIC this is not being exported so tp_mock.so won't
// load because of undefined symbol error. 
SO_PUBLIC void ErrorMessage(const char* format,...)
{
    va_list ap;
    va_start(ap,format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

SO_PUBLIC [[noreturn]] void FatalError(const char* format,...)
{
    ErrorMessage(format);
    exit(1);
}


SO_PUBLIC void WarningMessage(const char* format,...)
{
    va_list ap;
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
}

SO_PUBLIC void LogMessage(const char* format,...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}
}
#endif

