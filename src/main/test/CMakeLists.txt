if ( ENABLE_SHELL )
    add_cpputest(distill_verdict_test
        SOURCES
            distill_verdict_stubs.h
            ../analyzer.cc
            ../../packet_io/active.cc
    )
endif ( ENABLE_SHELL )
