
# this test is broken, uncomment below when fixed
# add_cpputest( tcp_normalizer_test
#     SOURCES
#         ../tcp_normalizer.cc
#         ../tcp_normalizers.cc
#         ../../../protocols/tcp_options.cc
#         ../../../main/snort_debug.cc
# )

add_cpputest( tcp_overlap_resolver_test
    SOURCES
        ../tcp_overlap_resolver.cc
)
