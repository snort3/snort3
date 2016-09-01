set (
    BINDER_TEST_LIBS
    flow
    framework
    stream
    stream_paf
)

add_cpputest(binder_test binder ${BINDER_TEST_LIBS})
