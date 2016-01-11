set ( _SAVE_CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS} )
set ( CMAKE_REQUIRED_FLAGS "-std=c++11 -fPIC -shared -Wl,-undefined,dynamic_lookup" )

unset ( HAVE_EXTERN_GNU_TLS )
check_cxx_source_compiles (
    "extern __thread int x; void foo() { ++x; }"
    HAVE_EXTERN_GNU_TLS
    )

unset (HAVE_THREAD_LOCAL )
check_cxx_source_compiles (
    "thread_local int x;"
    HAVE_THREAD_LOCAL
    )

unset ( USE_THREAD_LOCAL )
if ( NOT HAVE_EXTERN_GNU_TLS )
    if ( HAVE_THREAD_LOCAL )
        set ( USE_THREAD_LOCAL TRUE CACHE INTERNAL "Use thread_local keyword" )
    else ( HAVE_THREAD_LOCAL )
        message (
            SEND_ERROR
            "Compiler does not support thread_local OR extern __thread declarations"
        )
    endif ( HAVE_THREAD_LOCAL )
endif ( NOT HAVE_EXTERN_GNU_TLS )

set ( CMAKE_REQUIRED_FLAGS ${_SAVE_CMAKE_REQUIRED_FLAGS} )
