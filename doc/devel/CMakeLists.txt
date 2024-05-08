
set (
    UNBUILT_SOURCES
    snort_devel.txt
    extending.txt
    style.txt
    versions.txt
)

foreach ( file_name ${UNBUILT_SOURCES} )
    list (
        APPEND
        LIST_DIR_SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/${file_name}"
    )
endforeach ( file_name )

set ( BUILT_DIST ${BINARY_DIR_BUILT_SOURCES} ${BINARY_DIR_UNBUILT_SOURCES} )

add_custom_command (
    OUTPUT version.txt
    COMMAND $<TARGET_FILE:snort> -V 2>&1 | grep -o "Version.*$" > version.txt
    COMMAND sed -i -e "s/Version/:revnumber:/" version.txt
    COMMAND echo ":revdate: {localdate} {localtime}" >> version.txt
    DEPENDS snort
    COMMENT "Documents: building version.txt"
)

list ( APPEND BUILT_SOURCES version.txt )

add_custom_target (
    dev_built_sources
    DEPENDS ${BUILT_SOURCES}
)

if ( MAKE_HTML_DOC )

    set ( HTML_DOC_TMP "${CMAKE_CURRENT_BINARY_DIR}/html/" )

    add_custom_command (
        OUTPUT "${HTML_DOC_TMP}/"
        COMMAND mkdir -p ${HTML_DOC_TMP}
    )

    add_custom_command (
        OUTPUT snort_devel.html
        COMMAND mv ../${BUILT_SOURCES} ./
        COMMAND cp ${LIST_DIR_SOURCES} ${BINARY_DIR_BUILT_SOURCES} ./
        COMMAND ${CMAKE_CURRENT_LIST_DIR}/snort_devel.sh ${CMAKE_SOURCE_DIR}
        COMMAND mv snort_devel.html ../
        DEPENDS dev_built_sources "${HTML_DOC_TMP}/"
        WORKING_DIRECTORY ${HTML_DOC_TMP}
        COMMENT "Documents: building dev guide"
    )

    add_custom_target (
        docs-devel-html
        DEPENDS snort_devel.html
    )

endif ( MAKE_HTML_DOC )

install (
    FILES
    ${BUILT_DIST}
    ${UNBUILT_SOURCES}
    DESTINATION
    ${CMAKE_INSTALL_DOCDIR}
)

set (
    EXTRA_CLEAN
    ${EXTRA_CLEAN}
    ${BINARY_DIR_BUILT_SOURCES}
)

if ( NOT CMAKE_CURRENT_LIST_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR )
    list (
        APPEND
        EXTRA_CLEAN
        ${BINARY_DIR_UNBUILT_SOURCES}
    )
endif ()

if ( EXTRA_CLEAN )
    set_property (
        DIRECTORY
        PROPERTY
        ADDITIONAL_MAKE_CLEAN_FILES ${EXTRA_CLEAN}
    )
endif ( EXTRA_CLEAN )

