
include_directories(${PROJECT_SOURCE_DIR}/src/loggers)

add_executable( u2spewfoo
    u2spewfoo.cc
)

install (TARGETS u2spewfoo
    RUNTIME DESTINATION bin
)

#u2spewfoo_CFLAGS = @CFLAGS@ $(AM_CFLAGS)
#AM_CXXFLAGS = @AM_CXXFLAGS@ @extra_incl@
