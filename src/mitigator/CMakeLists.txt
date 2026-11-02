if ( CRASH_MITIGATOR )

add_subdirectory(test)

set (INCLUDES
    mitigator.h
    mitigator_action_exception.h
    mitigator_exception.h
    mitigator_helpers.h
    mitigator_module.h
    mitigator_types.h
)

set ( MITIGATOR_SOURCES
    mitigator.cc
    mitigator.h
    mitigator_action_exception.h
    mitigator_context_processor.cc
    mitigator_context_processor.h
    mitigator_exception.cc
    mitigator_exception.h
    mitigator_helpers.h
    mitigator_module.cc
    mitigator_module.h
    mitigator_types.h
)

add_library(mitigator STATIC
    ${MITIGATOR_SOURCES}
)

endif ( CRASH_MITIGATOR )

install (FILES ${INCLUDES} mitigator_api.h
    DESTINATION "${INCLUDE_INSTALL_PATH}/mitigator"
)

