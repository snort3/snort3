#ifndef CPP_MACROS_H
#define CPP_MACROS_H

#define STRINGIFY(x) #x

#if defined(__clang__) && !defined(__ICC)
#  define PADDING_GUARD_BEGIN \
    _Pragma(STRINGIFY( clang diagnostic push )) \
    _Pragma(STRINGIFY( clang diagnostic warning "-Wpadded" ))
#  define PADDING_GUARD_END \
    _Pragma(STRINGIFY( clang diagnostic pop ))
#elif defined(__GNUC__) && __GNUC__ > 4 && !defined(__ICC)
#  define PADDING_GUARD_BEGIN \
    _Pragma(STRINGIFY( GCC diagnostic push )) \
    _Pragma(STRINGIFY( GCC diagnostic warning "-Wpadded" ))
#  define PADDING_GUARD_END \
    _Pragma(STRINGIFY( GCC diagnostic pop ))
#else
#  define PADDING_GUARD_BEGIN
#  define PADDING_GUARD_END
#endif

#endif
