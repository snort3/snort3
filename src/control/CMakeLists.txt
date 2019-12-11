
add_library ( control OBJECT
    idle_processing.h
    idle_processing.cc
)

add_catch_test( idle_processing_test
    NO_TEST_SOURCE
    SOURCES
        idle_processing.cc
)
